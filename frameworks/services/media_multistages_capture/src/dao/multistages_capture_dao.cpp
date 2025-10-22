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

#define MLOG_TAG "MultiStagesCapture"

#include "multistages_capture_dao.h"

#include "medialibrary_tracer.h"
#include "medialibrary_command.h"
#include "media_column.h"
#include "medialibrary_operation.h"
#include "userfile_manager_types.h"
#include "database_adapter.h"
#include "media_log.h"
#include "multistages_capture_request_task_manager.h"
#include "medialibrary_errno.h"

namespace OHOS::Media {
int32_t MultiStagesCaptureDao::UpdatePhotoDirtyNew(const int32_t fileId)
{
    MediaLibraryTracer tracer;
    tracer.Start("UpdatePhotoDirtyNew, fileId: " + std::to_string(fileId));
    MediaLibraryCommand updateCmd(OperationObject::FILESYSTEM_PHOTO, OperationType::UPDATE);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, fileId);
    updateCmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, false);
    updateCmd.GetAbsRdbPredicates()->NotEqualTo(
        PhotoColumn::PHOTO_SUBTYPE, std::to_string(static_cast<int32_t>(PhotoSubType::MOVING_PHOTO)));
    NativeRdb::ValuesBucket updateValuesDirty;
    updateValuesDirty.PutInt(PhotoColumn::PHOTO_DIRTY, static_cast<int32_t>(DirtyType::TYPE_NEW));
    updateCmd.SetValueBucket(updateValuesDirty);
    auto isDirtyResult = DatabaseAdapter::Update(updateCmd);
    CHECK_AND_PRINT_LOG(isDirtyResult != E_OK, "update dirty flag fail, fileId: %{public}d", fileId);
    return isDirtyResult;
}

std::shared_ptr<NativeRdb::ResultSet> MultiStagesCaptureDao::QueryPhotoDataById(
    const std::string &imageId)
{
    int32_t fileId = MultiStagesCaptureRequestTaskManager::GetProcessingFileId(imageId);
    MediaLibraryCommand cmd(OperationObject::FILESYSTEM_PHOTO, OperationType::QUERY);
    if (fileId == E_ERR) {
        MEDIA_WARN_LOG("get fileId from fileId2PhotoId_ failed");
        cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::PHOTO_ID, imageId);
    } else {
        cmd.GetAbsRdbPredicates()->EqualTo(PhotoColumn::MEDIA_ID, fileId);
    }
    vector<string> columns { MediaColumn::MEDIA_ID, MediaColumn::MEDIA_FILE_PATH, PhotoColumn::PHOTO_EDIT_TIME,
        PhotoColumn::MEDIA_NAME, MediaColumn::MEDIA_MIME_TYPE, PhotoColumn::PHOTO_SUBTYPE, PhotoColumn::PHOTO_IS_TEMP,
        PhotoColumn::PHOTO_ORIENTATION, PhotoColumn::MEDIA_TYPE, MediaColumn::MEDIA_DATE_TRASHED };
    return DatabaseAdapter::Query(cmd, columns);
}

}  // namespace OHOS::Media