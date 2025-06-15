/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef REPAIR_NO_ORIGIN_PHOTO_PROCESSOR_H
#define REPAIR_NO_ORIGIN_PHOTO_PROCESSOR_H

#include "medialibrary_base_bg_processor.h"

#include <mutex>
#include <string>
#include <vector>

namespace OHOS {
namespace Media {
#define EXPORT __attribute__ ((visibility ("default")))
struct CheckedPhotoInfo {
    int32_t fileId;
    std::string path;
    int64_t size;
    int32_t subtype;
    int32_t movingPhotoEffectMode;
};

class RepairNoOriginPhotoPrecessor final : public MediaLibraryBaseBgProcessor {
public:
    RepairNoOriginPhotoPrecessor() {}
    ~RepairNoOriginPhotoPrecessor() {}

    int32_t Start(const std::string &taskExtra) override;
    int32_t Stop(const std::string &taskExtra) override;

private:
    void RepairNoOriginPhoto();

    void HandleNoOriginPhoto();
    std::vector<CheckedPhotoInfo> QueryPhotoInfo(int32_t startFiled);
    void HandlePhotoInfos(const std::vector<CheckedPhotoInfo> &photoInfos, int32_t &curFileId);
    void UpdateDirty(const std::vector<std::string> &idList, int32_t dirtyType);
    int32_t QueryLcdPhotoCount(int32_t startFileId);
    void UpdateFileSize(const CheckedPhotoInfo &photoInfo, bool isMovingPhoto);
    void HandleMissingFile(
        const CheckedPhotoInfo &photoInfo, bool isMovingPhoto, std::vector<std::string> &noLcdList);

    static std::mutex mutex_;
    const std::string taskName_ = REPAIR_NO_ORIGIN_PHOTO;
    bool taskStop_ {false};
};
} // namespace Media
} // namespace OHOS
#endif  // REPAIR_NO_ORIGIN_PHOTO_PROCESSOR_H
