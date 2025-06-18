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

#define MLOG_TAG "MediaBgTask_CleanInvalidCloudAlbumAndDataProcessor"

#include "clean_invalid_cloud_album_and_data_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_log.h"
#include "medialibrary_album_fusion_utils.h"
#include "medialibrary_errno.h"
#include "photo_album_lpath_operation.h"

namespace OHOS {
namespace Media {
int32_t CleanInvalidCloudAlbumAndDataProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        MediaLibraryAlbumFusionUtils::CleanInvalidCloudAlbumAndData();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t CleanInvalidCloudAlbumAndDataProcessor::Stop(const std::string &taskExtra)
{
    PhotoAlbumLPathOperation::GetInstance().Stop();
    return E_OK;
}
} // namespace Media
} // namespace OHOS
