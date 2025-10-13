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

#include <fcntl.h>
#include <sys/stat.h>

#include "video_3dgs_operation.h"

#include "directory_ex.h"

#include "abs_rdb_predicates.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_subscriber.h"
#include "medialibrary_unistore_manager.h"
#include "metadata_extractor.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "values_bucket.h"
#include "medialibrary_type_const.h"
#include "preferences.h"
#include "preferences_helper.h"
#include "medialibrary_rdb_utils.h"
#include "medialibrary_tracer.h"

using namespace OHOS::NativeRdb;

namespace OHOS::Media {
const std::string ORIGIN_3DGS_NUMBER = "origin_3DGS_number";
const std::int32_t BATCH_SIZE = 500;
const std::string TASK_PROGRESS_XML = "/data/storage/el2/base/preferences/task_progress.xml";
const std::string SQL_PHOTOS_TABLE_QUERY_VIDEO_COUNT = "SELECT"
                                                        " COUNT( * ) AS Count "
                                                        "FROM"
                                                        " Photos "
                                                        "WHERE"
                                                        " media_type = 2"
                                                        " AND subtype = 0"
                                                        " AND file_id > ?;";

const std::string SQL_PHOTOS_TABLE_QUERY_DEFAULT_SUBTYPE_VIDEO = "SELECT"
                                                                 " file_id,"
                                                                 " data "
                                                                 "FROM"
                                                                 " Photos "
                                                                 "WHERE"
                                                                 " media_type = 2"
                                                                 " AND subtype = 0"
                                                                 " AND file_id > ?"
                                                                 " LIMIT ?;";

std::atomic<bool> Video3DgsOperation::isContinue_{true};

void Video3DgsOperation::Stop()
{
    isContinue_.store(false);
}

void Video3DgsOperation::Update3DgsType()
{
    MEDIA_INFO_LOG("start handle 3DGS video!");
    isContinue_.store(true);
    int64_t startTime = MediaFileUtils::UTCTimeMilliSeconds();
    int32_t errCode = E_OK;
    shared_ptr<NativePreferences::Preferences> prefs =
        NativePreferences::PreferencesHelper::GetPreferences(TASK_PROGRESS_XML, errCode);
    CHECK_AND_RETURN_LOG(prefs, "get preferences error: %{public}d", errCode);
    int32_t curFileId = prefs->GetInt(ORIGIN_3DGS_NUMBER, 0);
    MEDIA_INFO_LOG("start file id: %{public}d", curFileId);
    while (MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load() && QueryVideoCount(curFileId) > 0) {
        MEDIA_INFO_LOG("handle 3DGS video curFileId: %{public}d", curFileId);
        std::vector<CheckedVideoInfo> photoInfos = QueryVideoInfo(curFileId);
        HandleVideoInfos(photoInfos, curFileId);
    }
    prefs->PutInt(ORIGIN_3DGS_NUMBER, curFileId);
    prefs->FlushSync();
    MEDIA_INFO_LOG(
        "end handle no origin photo! cost: %{public}" PRId64, MediaFileUtils::UTCTimeMilliSeconds() - startTime);
    return;
}

int32_t Video3DgsOperation::QueryVideoCount(int32_t startFileId)
{
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, E_HAS_DB_ERROR, "Failed to get rdbStore.");
    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_VIDEO_COUNT, bindArgs);
    CHECK_AND_RETURN_RET_LOG(
        resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK, 0, "resultSet is null or count is 0");
    return get<int32_t>(ResultSetUtils::GetValFromColumn("Count", resultSet, TYPE_INT32));
}

std::vector<CheckedVideoInfo> Video3DgsOperation::QueryVideoInfo(int32_t startFileId)
{
    std::vector<CheckedVideoInfo> photoInfos;
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, photoInfos, "Failed to get rdbstore!");

    const std::vector<NativeRdb::ValueObject> bindArgs = {startFileId, BATCH_SIZE};
    auto resultSet = rdbStore->QuerySql(SQL_PHOTOS_TABLE_QUERY_DEFAULT_SUBTYPE_VIDEO, bindArgs);
    bool cond = resultSet != nullptr && resultSet->GoToFirstRow() == NativeRdb::E_OK;
    CHECK_AND_RETURN_RET_LOG(cond, photoInfos, "resultSet is null or count is 0");

    do {
        std::string path =
            get<std::string>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_FILE_PATH, resultSet, TYPE_STRING));
        CHECK_AND_CONTINUE_ERR_LOG(!path.empty(), "Failed to get data path");
        CheckedVideoInfo photoInfo;
        photoInfo.fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MediaColumn::MEDIA_ID, resultSet, TYPE_INT32));
        photoInfo.path = path;
        photoInfos.push_back(photoInfo);
    } while (MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load() &&
        resultSet->GoToNextRow() == NativeRdb::E_OK);
    return photoInfos;
}

void Video3DgsOperation::HandleVideoInfos(const std::vector<CheckedVideoInfo> &photoInfos, int32_t &curFileId)
{
    for (const CheckedVideoInfo &photoInfo : photoInfos) {
        CHECK_AND_BREAK_INFO_LOG(MedialibrarySubscriber::IsCurrentStatusOn() && isContinue_.load(),
            "current status is off, break");
        curFileId = photoInfo.fileId;
        UpdateVideoSubtype(photoInfo);
    }
}

void Video3DgsOperation::UpdateVideoSubtype(const CheckedVideoInfo &photoInfo)
{
    std::unique_ptr<Metadata> data = make_unique<Metadata>();
    data->SetFilePath(photoInfo.path);
    data->SetFileName(MediaFileUtils::GetFileName(photoInfo.path));
    data->SetFileMediaType(MEDIA_TYPE_VIDEO);
    MetadataExtractor::ExtractAVMetadata(data);
    if (data->GetPhotoSubType() != static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS)) {
        MEDIA_DEBUG_LOG("The video is not 3DGS, file_id=%{public}d", photoInfo.fileId);
        return;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_LOG(rdbStore != nullptr, "rdbStore is nullptr");
    RdbPredicates predicates(PhotoColumn::PHOTOS_TABLE);
    predicates.EqualTo(MediaColumn::MEDIA_ID, photoInfo.fileId);

    ValuesBucket values;
    values.PutInt(PhotoColumn::PHOTO_SUBTYPE, static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS));
    values.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyTypes::TYPE_NEW));

    int32_t updateCount = 0;
    int32_t err = rdbStore->Update(updateCount, values, predicates);

    CHECK_AND_RETURN_LOG(err == NativeRdb::E_OK,
        "Update video subtype failed, file_id=%{public}d, err=%{public}d", photoInfo.fileId, err);

    MEDIA_INFO_LOG("Update video subtype success, file_id=%{public}d, updated_rows=%{public}d", photoInfo.fileId,
        updateCount);
}
}  // namespace OHOS::Media