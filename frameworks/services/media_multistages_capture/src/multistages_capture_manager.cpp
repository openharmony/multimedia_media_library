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

#define MLOG_TAG "MultiStagesCaptureManager"

#include "multistages_capture_manager.h"


#include "media_log.h"
#include "medialibrary_rdbstore.h"
#include "result_set_utils.h"

using namespace std;

namespace OHOS {
namespace Media {

MultiStagesCaptureManager::MultiStagesCaptureManager() {}

MultiStagesCaptureManager::~MultiStagesCaptureManager() {}

void MultiStagesCaptureManager::RemovePhotos(const NativeRdb::AbsRdbPredicates &predicates,
    bool isRestorable)
{
    MEDIA_INFO_LOG("Remove photos enter, isRestorable is: %{public}d", isRestorable);
    if (predicates.GetTableName() != PhotoColumn::PHOTOS_TABLE) {
        MEDIA_INFO_LOG("Invalid table name: %{public}s", predicates.GetTableName().c_str());
        return;
    }

    NativeRdb::AbsRdbPredicates predicatesNew(predicates.GetTableName());
    string where = predicates.GetWhereClause() + " AND " + PhotoColumn::PHOTO_QUALITY + "=" +
        to_string(static_cast<int32_t>(MultiStagesPhotoQuality::LOW));

    predicatesNew.SetWhereClause(where);
    predicatesNew.SetWhereArgs(predicates.GetWhereArgs());
    vector<string> columns { MediaColumn::MEDIA_ID, MEDIA_DATA_DB_PHOTO_ID, MEDIA_DATA_DB_PHOTO_QUALITY,
        MEDIA_DATA_DB_MEDIA_TYPE };
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicatesNew, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Result set is empty");
        return;
    }

    do {
        string photoId = GetStringVal(MEDIA_DATA_DB_PHOTO_ID, resultSet);
        int32_t photoQuality = GetInt32Val(MEDIA_DATA_DB_PHOTO_QUALITY, resultSet);
        if (photoId.empty() || photoQuality == static_cast<int32_t>(MultiStagesPhotoQuality::FULL)) {
            MEDIA_DEBUG_LOG("photoId is empty or full quality ");
            continue;
        }

        int32_t mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, resultSet);
        MEDIA_INFO_LOG("Media type is: %{public}d", mediaType);
        switch (mediaType) {
            case MediaType::MEDIA_TYPE_IMAGE:
                MultiStagesPhotoCaptureManager::GetInstance().RemoveImage(photoId, isRestorable);
                break;
            case MediaType::MEDIA_TYPE_VIDEO:
                MultiStagesVideoCaptureManager::GetInstance().RemoveVideo(photoId, isRestorable);
                break;
            default:
                break;
        }
    } while (!resultSet->GoToNextRow());
}

void MultiStagesCaptureManager::RestorePhotos(const NativeRdb::AbsRdbPredicates &predicates)
{
    MEDIA_INFO_LOG("Restore photos enter");
    if (predicates.GetTableName() != PhotoColumn::PHOTOS_TABLE) {
        MEDIA_INFO_LOG("Invalid table name: %{public}s", predicates.GetTableName().c_str());
        return;
    }

    NativeRdb::AbsRdbPredicates predicatesNew(predicates.GetTableName());
    string where = predicates.GetWhereClause() + " AND " + PhotoColumn::PHOTO_QUALITY + "=" +
        to_string(static_cast<int32_t>(MultiStagesPhotoQuality::LOW));
    predicatesNew.SetWhereClause(where);
    predicatesNew.SetWhereArgs(predicates.GetWhereArgs());
    vector<string> columns { MediaColumn::MEDIA_ID, MEDIA_DATA_DB_PHOTO_ID, MEDIA_DATA_DB_PHOTO_QUALITY,
        MEDIA_DATA_DB_MEDIA_TYPE };
    auto resultSet = MediaLibraryRdbStore::QueryWithFilter(predicatesNew, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_INFO_LOG("Result set is empty");
        return;
    }

    do {
        string photoId = GetStringVal(MEDIA_DATA_DB_PHOTO_ID, resultSet);
        int32_t photoQuality = GetInt32Val(MEDIA_DATA_DB_PHOTO_QUALITY, resultSet);
        if (photoId.empty() || photoQuality == static_cast<int32_t>(MultiStagesPhotoQuality::FULL)) {
            MEDIA_DEBUG_LOG("photoId is empty or full quality ");
            continue;
        }

        int32_t mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, resultSet);
        switch (mediaType) {
            case MediaType::MEDIA_TYPE_IMAGE:
                MultiStagesPhotoCaptureManager::GetInstance().RestoreImage(photoId);
                break;
            case MediaType::MEDIA_TYPE_VIDEO:
                MultiStagesVideoCaptureManager::GetInstance().RestoreVideo(photoId);
                break;
            default:
                break;
        }
    } while (!resultSet->GoToNextRow());
}
} // Media
} // OHOS