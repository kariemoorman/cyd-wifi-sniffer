#include "ml_inference.h"
#include "sniffer_model.h"
#include "scaler_params.h"
#include "label_mappings.h"
#include <Arduino.h>

#include "tensorflow/lite/micro/all_ops_resolver.h"
#include "tensorflow/lite/micro/micro_error_reporter.h"
#include "tensorflow/lite/micro/micro_interpreter.h"
#include "tensorflow/lite/schema/schema_generated.h"

static constexpr int kArenaSize = 24 * 1024;

bool MLInference::init() {
    arena_ = (uint8_t*)malloc(kArenaSize);
    if (!arena_) {
        Serial.println("ML: arena alloc failed");
        return false;
    }

    auto* mdl = tflite::GetModel(SNIFFER_MODEL);
    if (mdl->version() != TFLITE_SCHEMA_VERSION) {
        Serial.printf("ML: schema mismatch %lu vs %d\n", mdl->version(), TFLITE_SCHEMA_VERSION);
        free(arena_);
        arena_ = nullptr;
        return false;
    }

    auto* reporter = new tflite::MicroErrorReporter();
    auto* res = new tflite::AllOpsResolver();
    auto* interp = new tflite::MicroInterpreter(mdl, *res, arena_, kArenaSize, reporter);

    if (interp->AllocateTensors() != kTfLiteOk) {
        Serial.println("ML: AllocateTensors failed");
        delete interp;
        delete res;
        delete reporter;
        free(arena_);
        arena_ = nullptr;
        return false;
    }

    model_ = (void*)mdl;
    resolver_ = (void*)res;
    interpreter_ = (void*)interp;
    loaded_ = true;

    Serial.printf("ML: model loaded (%u bytes, arena %d)\n", SNIFFER_MODEL_LEN, kArenaSize);
    Serial.printf("ML: input tensor: %d dims\n", interp->input(0)->dims->data[1]);
    return true;
}

bool MLInference::predict(DeviceStats* dev) {
    if (!loaded_ || !dev || dev->pkt_count < 5) return false;

    auto* interp = (tflite::MicroInterpreter*)interpreter_;
    TfLiteTensor* input = interp->input(0);

    float features[N_FEATURES] = {
        (float)dev->pkt_count,
        dev->avg_pkt_size(),
        dev->std_pkt_size(),
        dev->avg_rssi(),
        dev->pkt_rate(),
        dev->mgmt_ratio(),
        dev->data_ratio(),
        dev->ctrl_ratio(),
        (float)dev->unique_dst_count,
        dev->beacon_rate(),
        dev->probe_req_rate(),
        dev->retry_ratio(),
    };

    float input_scale = input->params.scale;
    int32_t input_zp = input->params.zero_point;

    for (int i = 0; i < N_FEATURES; i++) {
        float normalized = (features[i] - FEATURE_MEAN[i]) / FEATURE_SCALE[i];
        int val = (int)(normalized / input_scale) + input_zp;
        if (val < -128) val = -128;
        if (val > 127) val = 127;
        input->data.int8[i] = (int8_t)val;
    }

    if (interp->Invoke() != kTfLiteOk) return false;

    struct { uint8_t* dst; int count; } heads[] = {
        {&dev->ml.anomaly,      ANOMALY_COUNT},
        {&dev->ml.packet_class, PACKET_CLASS_COUNT},
        {&dev->ml.protocol,     PROTOCOL_COUNT},
        {&dev->ml.device_type,  DEVICE_TYPE_COUNT},
        {&dev->ml.route_action, ROUTE_ACTION_COUNT},
    };

    for (int h = 0; h < 5; h++) {
        TfLiteTensor* output = interp->output(h);
        float out_scale = output->params.scale;
        int32_t out_zp = output->params.zero_point;
        int n = heads[h].count;

        int best = 0;
        float best_val = -1e9f;
        for (int j = 0; j < n; j++) {
            float val = (output->data.int8[j] - out_zp) * out_scale;
            if (val > best_val) {
                best_val = val;
                best = j;
            }
            if (h == 0 && j == 1) {
                dev->ml.anomaly_score = val;
            }
        }
        *heads[h].dst = (uint8_t)best;
    }

    dev->ml.valid = true;
    return true;
}

void MLInference::predict_all(FeatureExtractor& fe) {
    if (!loaded_) return;
    for (int i = 0; i < fe.device_count(); i++) {
        predict(&fe.get_devices()[i]);
    }
}
