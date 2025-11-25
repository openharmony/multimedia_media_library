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

#ifndef OHOS_MEDIA_SHOOTING_MODE_ALBUM_OPERATION_H
#define OHOS_MEDIA_SHOOTING_MODE_ALBUM_OPERATION_H

#include <string>
#include <vector>

#include "medialibrary_rdbstore.h"

namespace OHOS::Media {

struct CheckedShootingAssetsInfo {
    int32_t fileId;
    std::string path;
    int32_t mediaType;
};

class ShootingModeAlbumOperation {
public:
    static void UpdateShootingModeAlbum();
    static void Stop();

    //PRO_PHOTO、SLOW_MOTION、LIGHT_PAINTING、SUPER_MACRO、TIME_LAPSE、QUICK_CAPTURE_ALBUM
    static int32_t QueryShootingAssetsCount(int32_t startFileId);
    static std::vector<CheckedShootingAssetsInfo> QueryShootingAssetsInfo(int32_t startFileId);
    static void HandleInfos(const std::vector<CheckedShootingAssetsInfo> &photoInfos, int32_t &curFileId);
    static bool UpdateShootingAlbum(const CheckedShootingAssetsInfo &photoInfo);

private:
    static std::atomic<bool> isContinue_;
};
}  // namespace OHOS::Media
#endif  // OHOS_MEDIA_SHOOTING_MODE_ALBUM_OPERATION_H