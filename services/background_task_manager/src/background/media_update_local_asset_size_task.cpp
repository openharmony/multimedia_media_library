/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "Media_Background"

#include "media_update_local_asset_size_task.h"

#include "media_column.h"
#include "media_log.h"
#include "medialibrary_asset_operations.h"
#include "medialibrary_command.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_tracer.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS::Media::Background {
static const int32_t BATCH_QUERY_FILE_NUMBER = 200;

bool MediaUpdateLocalAssetSizeTask::Accept()
{
    return MedialibrarySubscriber::IsCurrentStatusOn();
}

void MediaUpdateLocalAssetSizeTask::Execute()
{
    MEDIA_INFO_LOG("MediaUpdateLocalAssetSizeTask Execute begin.");

    while (Accept()) {
        QueryLocalAssetSizeStatus status = HandleUpdateLocalAssetSizeTask();
        if (status == QueryLocalAssetSizeStatus::NONE_DATA) {
            break;
        }
        MEDIA_INFO_LOG("HandleUpdateLocalAssetSizeTask loop once.");
    }

    MEDIA_INFO_LOG("MediaUpdateLocalAssetSizeTask Execute end.");
}

static int64_t GetLocalAssetSize(const std::shared_ptr<FileAsset>& fileAsset)
{
    CHECK_AND_RETURN_RET_LOG(fileAsset != nullptr, 0, "fileAsset is nullptr.");
    if (fileAsset->GetMovingPhotoEffectMode() != static_cast<int32_t>(MovingPhotoEffectMode::IMAGE_ONLY)) {
        return fileAsset->GetSize();
    }

    std::string imagePath = fileAsset->GetPath();
    size_t size = 0;
    if (!MediaFileUtils::GetFileSize(imagePath, size) || size == 0) {
        MEDIA_ERR_LOG("Failed to GetFileSize, imagePath: %{private}s, size: %{public}zu, errno: %{public}d",
            imagePath.c_str(), size, errno);
        return 0;
    }
    return static_cast<int64_t>(size);
}

QueryLocalAssetSizeStatus MediaUpdateLocalAssetSizeTask::HandleUpdateLocalAssetSizeTask()
{
    auto fileAssets = QueryAssetsFromDb();
    if (fileAssets.empty()) {
        MEDIA_INFO_LOG("There is no data need to process for local_asset_size.");
        return QueryLocalAssetSizeStatus::NONE_DATA;
    }

    for (const auto& fileAsset : fileAssets) {
        if (fileAsset == nullptr) {
            continue;
        }

        // 识别是否需要特殊处理
        int64_t localAssetSize = GetLocalAssetSize(fileAsset);
        if (localAssetSize == 0) {
            continue;
        }
        UpdateLocalAssetSizeToDb(fileAsset->GetId(), localAssetSize);
    }
    return QueryLocalAssetSizeStatus::E_OK;
}

std::vector<std::shared_ptr<FileAsset>> MediaUpdateLocalAssetSizeTask::QueryAssetsFromDb()
{
    MediaLibraryTracer tracer;
    tracer.Start("MediaUpdateLocalAssetSizeTask::QueryAssetsFromDb");
    MEDIA_INFO_LOG("QueryAssetsFromDb begin.");

    const std::vector<std::string> QUERY_COLUMNS = {
        MediaColumn::MEDIA_ID,
        MediaColumn::MEDIA_FILE_PATH,
        MediaColumn::MEDIA_SIZE,
        PhotoColumn::PHOTO_SUBTYPE,
        PhotoColumn::MOVING_PHOTO_EFFECT_MODE,
    };

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    // 回收站数据、隐藏相册数据也需要处理
    cmd.GetAbsRdbPredicates()->EqualTo(MediaColumn::MEDIA_TIME_PENDING, 0);
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, 0);

    // 处理原则: [1] size 存在, 但 local_asset_size 不存在的非纯云数据。
    //          [2] 为了确保最大程度满足使用, 根据 date_taken 倒序进行处理
    cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::LOCAL_ASSET_SIZE, 0);
    cmd.GetAbsRdbPredicates()->NotEqualTo(MediaColumn::MEDIA_SIZE, 0);
    cmd.GetAbsRdbPredicates()->NotEqualTo(PhotoColumn::PHOTO_POSITION, static_cast<int32_t>(PhotoPositionType::CLOUD));
    cmd.GetAbsRdbPredicates()->NotEqualTo(PhotoColumn::PHOTO_POSITION,
        static_cast<int32_t>(PhotoPositionType::INVALID));
    cmd.GetAbsRdbPredicates()->OrderByDesc(MediaColumn::MEDIA_DATE_TAKEN);
    cmd.GetAbsRdbPredicates()->Limit(BATCH_QUERY_FILE_NUMBER);

    std::vector<std::shared_ptr<FileAsset>> fileAssetVec;
    int32_t errCode = MediaLibraryAssetOperations::GetFileAssetVectorFromDb(fileAssetVec, cmd, QUERY_COLUMNS);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, fileAssetVec, "Failed to query file asset, err: %{public}d.", errCode);

    MEDIA_INFO_LOG("QueryAssetsFromDb end.");
    return fileAssetVec;
}

int32_t MediaUpdateLocalAssetSizeTask::UpdateLocalAssetSizeToDb(const int32_t fileId, const int64_t localAssetSize)
{
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);
    ValuesBucket values;
    values.Put(PhotoColumn::LOCAL_ASSET_SIZE, localAssetSize);

    int32_t changeRows = MediaLibraryRdbStore::UpdateWithDateTime(values, predicates);
    if (changeRows <= 0) {
        MEDIA_ERR_LOG("Failed to UpdateWithDateTime, changeRows: %{public}d.", changeRows);
    }
    return changeRows;
}
}  // namespace OHOS::Media::Background