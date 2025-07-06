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

#define MLOG_TAG "MediaBgTask_DeleteCloudMediaAssetsProcessor"

#include "delete_cloud_media_assets_processor.h"

#include "cloud_media_asset_manager.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_log.h"
#include "medialibrary_errno.h"

namespace OHOS {
namespace Media {
int32_t DeleteCloudMediaAssetsProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        CloudMediaAssetManager::GetInstance().StartDeleteCloudMediaAssets();
    });
    return E_OK;
}

int32_t DeleteCloudMediaAssetsProcessor::Stop(const std::string &taskExtra)
{
    CloudMediaAssetManager::GetInstance().StopDeleteCloudMediaAssets();
    return E_OK;
}
} // namespace Media
} // namespace OHOS
