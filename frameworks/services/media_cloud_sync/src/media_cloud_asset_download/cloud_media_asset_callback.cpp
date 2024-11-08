/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CLOUD_MEDIA_ASSET_CALLBACK_H
#define OHOS_CLOUD_MEDIA_ASSET_CALLBACK_H

#include "cloud_media_asset_callback.h"

#include <string>

#include "cloud_media_asset_download_operation.h"
#include "media_log.h"

using namespace std;

namespace OHOS {
namespace Media {

void MediaCloudDownloadCallback::OnDownloadProcess(const DownloadProgressObj& progress)
{
    switch (progress.state) {
        case DownloadProgressObj::Status::COMPLETED: {
            if (progress.downloadErrorType == static_cast<int32_t>(DownloadProgressObj::DownloadErrorType::NO_ERROR)) {
                operation_->HandleSuccessCallback(progress);
            }
            break;
        }
        case DownloadProgressObj::Status::FAILED: {
            operation_->HandleFailedCallback(progress);
            break;
        }
        case DownloadProgressObj::Status::STOPPED: {
            operation_->HandleStoppedCallback(progress);
            break;
        }
        default: {
            return;
        }
    }
}
} // namespace Media
} // namespace OHOS
#endif // OHOS_CLOUD_MEDIA_ASSET_OBSERVER_H