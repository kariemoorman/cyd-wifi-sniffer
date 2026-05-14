#pragma once

#include "feature_extractor.h"

class MLInference {
public:
    bool init();
    bool predict(DeviceStats* dev);
    void predict_all(FeatureExtractor& fe);
    bool is_loaded() const { return loaded_; }

private:
    bool loaded_ = false;
    uint8_t* arena_ = nullptr;
    void* interpreter_ = nullptr;
    void* model_ = nullptr;
    void* resolver_ = nullptr;
};
