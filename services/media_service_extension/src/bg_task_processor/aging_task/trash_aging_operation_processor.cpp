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

#define MLOG_TAG "MediaBgTask_TrashAgingOperationProcessor"

#include "trash_aging_operation_processor.h"

#include "dfx_utils.h"
#include "directory_ex.h"
#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_audio_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_tab_asset_and_album_operations.h"
#include "medialibrary_unistore_manager.h"
#include "photo_album_column.h"
#include "photo_custom_restore_operation.h"
#include "post_event_utils.h"

#include <string>
#include <vector>

namespace OHOS {
namespace Media {
int32_t TrashAgingOperationProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        DoAgingOperation();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t TrashAgingOperationProcessor::Stop(const std::string &taskExtra)
{
    taskStop_ = true;
    TrashInterruptWork();
    return E_OK;
}

void TrashAgingOperationProcessor::DoAgingOperation()
{
    CacheAging(); // aging file in .cache

    PhotoCustomRestoreOperation::GetInstance().CleanTimeoutCustomRestoreTaskDir();

    ClearInvalidDeletedAlbum(); // Clear invalid album data with null cloudid and dirty '4'

    MediaLibraryTableAssetAlbumOperations().OprnTableOversizeChecker();

    TrashStartWork();

    std::shared_ptr<int> trashCountPtr = std::make_shared<int>();
    int32_t result = DoTrashAging(trashCountPtr);
    CHECK_AND_PRINT_LOG(result == E_OK, "DoTrashAging faild");

    VariantMap map = {{KEY_COUNT, *trashCountPtr}};
    PostEventUtils::GetInstance().PostStatProcess(StatType::AGING_STAT, map);
}

void TrashAgingOperationProcessor::CacheAging()
{
    MEDIA_INFO_LOG("begin CacheAging");
    if (!MediaFileUtils::IsDirectory(MEDIA_CACHE_DIR)) {
        return;
    }
    time_t now = time(nullptr);
    constexpr int thresholdSeconds = 24 * 60 * 60; // 24 hours
    std::vector<std::string> files;
    GetDirFiles(MEDIA_CACHE_DIR, files);
    for (auto &file : files) {
        if (taskStop_) {
            MEDIA_INFO_LOG("bgtask schedule stop.");
            return;
        }
        struct stat statInfo {};
        if (stat(file.c_str(), &statInfo) != 0) {
            MEDIA_WARN_LOG("skip %{private}s, stat errno: %{public}d", file.c_str(), errno);
            continue;
        }
        time_t timeModified = statInfo.st_mtime;
        double duration = difftime(now, timeModified); // diff in seconds
        if (duration < thresholdSeconds) {
            continue;
        }
        if (!MediaFileUtils::DeleteFile(file)) {
            MEDIA_ERR_LOG("delete failed %{public}s, errno: %{public}d", file.c_str(), errno);
        }
    }
}

void TrashAgingOperationProcessor::ClearInvalidDeletedAlbum()
{
    MEDIA_INFO_LOG("begin ClearInvalidDeletedAlbum");
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }

    const std::string QUERY_NO_CLOUD_DELETED_ALBUM_INFO =
        "SELECT album_id, album_name FROM PhotoAlbum WHERE " +
        PhotoAlbumColumns::ALBUM_DIRTY + " = " + std::to_string(static_cast<int32_t>(DirtyTypes::TYPE_DELETED)) +
        " AND " + PhotoColumn::PHOTO_CLOUD_ID + " is NULL";
    std::shared_ptr<NativeRdb::ResultSet> resultSet = rdbStore->QuerySql(QUERY_NO_CLOUD_DELETED_ALBUM_INFO);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Query not match data fails");
        return;
    }

    std::vector<std::string> albumIds;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK && !taskStop_) {
        int columnIndex = 0;
        int32_t albumId = -1;
        if (resultSet->GetColumnIndex(PhotoAlbumColumns::ALBUM_ID, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetInt(columnIndex, albumId);
            albumIds.emplace_back(to_string(albumId));
        }
        std::string albumName = "";
        if (resultSet->GetColumnIndex(PhotoAlbumColumns::ALBUM_NAME, columnIndex) == NativeRdb::E_OK) {
            resultSet->GetString(columnIndex, albumName);
        }
        MEDIA_INFO_LOG("Handle name %{public}s id %{public}d", DfxUtils::GetSafeAlbumName(albumName).c_str(), albumId);
    }
    if (albumIds.size() == 0) {
        return;
    }

    NativeRdb::RdbPredicates predicates(PhotoAlbumColumns::TABLE);
    predicates.In(PhotoAlbumColumns::ALBUM_ID, albumIds);
    int deleteRow = -1;
    auto ret = rdbStore->Delete(deleteRow, predicates);
    MEDIA_INFO_LOG("Delete invalid album, deleteRow is %{public}d", deleteRow);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Delete invalid album failed, ret = %{public}d, deleteRow is %{public}d", ret, deleteRow);
        return;
    }
}

void TrashAgingOperationProcessor::TrashStartWork()
{
    MEDIA_INFO_LOG("Begin TrashStartWork");
    MediaLibrarySmartAlbumMapOperations::SetInterrupt(false);
    MediaLibrarySmartAlbumMapOperations::HandleAgingOperation();
    MediaLibraryAlbumOperations::HandlePhotoAlbum(OperationType::AGING, {}, {});
}

void TrashAgingOperationProcessor::TrashInterruptWork()
{
    MediaLibrarySmartAlbumMapOperations::SetInterrupt(true);
}

int32_t TrashAgingOperationProcessor::DoTrashAging(shared_ptr<int> countPtr)
{
    shared_ptr<int> smartAlbumTrashPtr = make_shared<int>();
    MediaLibrarySmartAlbumMapOperations::HandleAgingOperation(smartAlbumTrashPtr);

    shared_ptr<int> albumTrashtPtr = make_shared<int>();
    MediaLibraryAlbumOperations::HandlePhotoAlbum(OperationType::AGING, {}, {}, albumTrashtPtr);

    shared_ptr<int> audioTrashtPtr = make_shared<int>();
    MediaLibraryAudioOperations::TrashAging(audioTrashtPtr);

    if (countPtr != nullptr) {
      *countPtr = *smartAlbumTrashPtr + *albumTrashtPtr + *audioTrashtPtr;
    }
    return E_SUCCESS;
}
} // namespace Media
} // namespace OHOS
