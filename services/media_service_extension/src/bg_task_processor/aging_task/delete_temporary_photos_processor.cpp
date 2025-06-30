/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,DeleteTemporaryPhoto
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define MLOG_TAG "MediaBgTask_DeleteTemporaryPhotosProcessor"

#include "delete_temporary_photos_processor.h"

#include "ffrt.h"
#include "ffrt_inner.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "medialibrary_operation.h"
#include "medialibrary_photo_operations.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"

using namespace std;
namespace OHOS {
namespace Media {
static const int32_t BATCH_DELETE_COUNT = 200;
static const int32_t LIMIT_COUNT_WITHIN_ONE_DAY = 100;
static const int32_t RETAIN_COUNT_WITHIN_ONE_DAY = 50;
static const int32_t STOP_FLAG = 10;

int32_t DeleteTemporaryPhotosProcessor::Start(const std::string &taskExtra)
{
    MEDIA_INFO_LOG("Start begin");
    ffrt::submit([this]() {
        DeleteTemporaryPhotos();
        RemoveTaskName(taskName_);
        ReportTaskComplete(taskName_);
    });
    return E_OK;
}

int32_t DeleteTemporaryPhotosProcessor::Stop(const std::string &taskExtra)
{
    taskStop_ = true;
    return E_OK;
}

std::shared_ptr<NativeRdb::ResultSet> DeleteTemporaryPhotosProcessor::QueryAllTempPhoto(int32_t &count,
    bool isOverOneDay)
{
    // 打断
    if (taskStop_) {
        MEDIA_INFO_LOG("bgtask schedule stop.");
        return nullptr;
    }
    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    CHECK_AND_RETURN_RET_LOG(rdbStore != nullptr, nullptr, "rdbStore is nullptr!");

    NativeRdb::AbsRdbPredicates queryPredicates(PhotoColumn::PHOTOS_TABLE);
    queryPredicates.EqualTo(PhotoColumn::PHOTO_IS_TEMP, "1");
    if (isOverOneDay) {
        int64_t current = MediaFileUtils::UTCTimeMilliSeconds();
        int64_t timeBefore24Hours = current - 24 * 60 * 60 * 1000;
        queryPredicates.LessThan(PhotoColumn::MEDIA_DATE_ADDED, to_string(timeBefore24Hours));
    } else {
        queryPredicates.OrderByDesc(MediaColumn::MEDIA_ID);
    }

    std::vector<std::string> columns = { MediaColumn::MEDIA_ID };
    auto resultSet = rdbStore->Query(queryPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, nullptr, "resultSet is null");
    if (resultSet->GetRowCount(count) != NativeRdb::E_OK || count < 0) {
        MEDIA_ERR_LOG("GetRowCount fail");
        resultSet->Close();
        return nullptr;
    }
    return resultSet;
}

void DeleteTemporaryPhotosProcessor::DeleteAllTempPhotoOverOneDay()
{
    MEDIA_INFO_LOG("DeleteAllTempPhotoOverOneDay begin");
    int32_t count = 0;
    auto resultSet = QueryAllTempPhoto(count, true);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "resultSet is null");
    if (count == 0) {
        MEDIA_INFO_LOG("No need DeleteAllTempPhotoOverOneDay, There is no temporary photo for more than 24 hours.");
        resultSet->Close();
        return;
    }

    MEDIA_INFO_LOG("do DeleteAllTempPhotoOverOneDay, count: %{public}d.", count);
    std::vector<std::string> fileIds;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
        if (fileId.empty()) {
            MEDIA_WARN_LOG("Failed to get fileId!");
            continue;
        }
        if (fileIds.size() > BATCH_DELETE_COUNT) {
            if (DeleteTempPhotoExecute(fileIds) == STOP_FLAG) {
                MEDIA_INFO_LOG("bgtask schedule stop.");
                resultSet->Close();
                return;
            }
            fileIds.clear();
        }
        fileIds.emplace_back(fileId);
    }
    DeleteTempPhotoExecute(fileIds);
    resultSet->Close();
    MEDIA_INFO_LOG("success DeleteAllTempPhotoOverOneDay, count: %{public}d.", count);
}

void DeleteTemporaryPhotosProcessor::DeleteTempPhotoMoreThanHundred()
{
    MEDIA_INFO_LOG("DeleteTempPhotoMoreThanHundred begin");
    int32_t count = 0;
    auto resultSet = QueryAllTempPhoto(count, false);
    CHECK_AND_RETURN_LOG(resultSet != nullptr, "resultSet is null");
    if (count <= LIMIT_COUNT_WITHIN_ONE_DAY) {
        MEDIA_INFO_LOG("The number of temporary photo no more than 100, count: %{public}d.", count);
        resultSet->Close();
        return;
    }

    MEDIA_INFO_LOG("do DeleteTempPhotoMoreThanHundred, count: %{public}d.", count);
    std::vector<std::string> fileIds;
    int32_t retainCount = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        if (retainCount < RETAIN_COUNT_WITHIN_ONE_DAY) {
            retainCount++;
            continue;
        }

        std::string fileId = GetStringVal(MediaColumn::MEDIA_ID, resultSet);
        if (fileId.empty()) {
            MEDIA_WARN_LOG("Failed to get fileId!");
            continue;
        }
        if (fileIds.size() > BATCH_DELETE_COUNT) {
            if (DeleteTempPhotoExecute(fileIds) == STOP_FLAG) {
                MEDIA_INFO_LOG("bgtask schedule stop.");
                resultSet->Close();
                return;
            }
            fileIds.clear();
        }
        fileIds.emplace_back(fileId);
    }
    DeleteTempPhotoExecute(fileIds);
    resultSet->Close();
    MEDIA_INFO_LOG("success DeleteTempPhotoMoreThanHundred, count: %{public}d.", count);
}

int32_t DeleteTemporaryPhotosProcessor::DeleteTempPhotoExecute(std::vector<std::string> &fileIds)
{
    // 打断
    if (taskStop_ || fileIds.empty()) {
        MEDIA_INFO_LOG("bgtask schedule stop, wait for deleteRows: %{public}d.", static_cast<int32_t>(fileIds.size()));
        return STOP_FLAG;
    }

    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    DataShare::DataSharePredicates predicates;
    predicates.In(MediaColumn::MEDIA_ID, fileIds);
    cmd.SetDataSharePred(predicates);

    int32_t ret = MediaLibraryPhotoOperations::DiscardCameraPhoto(cmd);
    CHECK_AND_RETURN_RET_LOG(ret > 0, E_ERR, "Failed to DiscardCameraPhoto, ret: %{public}d.", ret);
    MEDIA_INFO_LOG("success DeleteTempPhotoExecute, deleteRow: %{public}d.", static_cast<int32_t>(fileIds.size()));
    return E_OK;
}

void DeleteTemporaryPhotosProcessor::DeleteTemporaryPhotos()
{
    MEDIA_INFO_LOG("DeleteTemporaryPhotos begin.");
    DeleteAllTempPhotoOverOneDay();
    DeleteTempPhotoMoreThanHundred();
    MEDIA_INFO_LOG("DeleteTemporaryPhotos end.");
}
} // namespace Media
} // namespace OHOS
