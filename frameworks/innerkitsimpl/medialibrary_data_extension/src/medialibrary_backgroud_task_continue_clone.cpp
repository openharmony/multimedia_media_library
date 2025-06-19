/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MedialibrarySubscribe"

#include "medialibrary_subscriber.h"

#include "medialibrary_restore.h"
#include "media_column.h"
#include "media_file_utils.h"
#include "media_log.h"

#include "medialibrary_errno.h"
#include "file_ex.h"
#include <nlohmann/json.hpp>
#include <memory>

using namespace OHOS::AAFwk;
using namespace std;
namespace OHOS {
namespace Media {
const int32_t SECONDS_TO_MS = 1000;
const int32_t MS_OF_ONE_DAY = 24 * 60 * 60 * 1000;
static const std::string DATA_CLONE_DESCRIPTION_JSON =
    PhotoColumn::FILES_LOCAL_DIR + ".backup/restore/dataclone_description.json";
const static std::string CLONE_TIME_STAMP = "cloneTimestamp";
const static std::string CLONE_FOLDER_PATH = PhotoColumn::FILES_LOCAL_DIR + ".backup/clone";
const static std::string RESTORE_FOLDER_PATH = PhotoColumn::FILES_LOCAL_DIR + ".backup/restore";

void MedialibrarySubscriber::ClearContinueCloneData(AsyncTaskData *data)
{
    bool clearCloneFolder = MediaFileUtils::DeleteDir(CLONE_FOLDER_PATH);
    bool clearRestoreFolder = MediaFileUtils::DeleteDir(RESTORE_FOLDER_PATH);
    MEDIA_INFO_LOG("ClearContinueCloneData success clearCloneFolder:%{public}d clearRestoreFolder:%{public}d",
        clearCloneFolder, clearRestoreFolder);
}

int32_t MedialibrarySubscriber::DoClearContinueCloneData()
{
    auto asyncWorker = MediaLibraryAsyncWorker::GetInstance();
    CHECK_AND_RETURN_RET_LOG(asyncWorker != nullptr, E_FAIL,
        "Failed to get async worker instance!");
    shared_ptr<MediaLibraryAsyncTask> ClearContinueCloneTask =
        make_shared<MediaLibraryAsyncTask>(ClearContinueCloneData, nullptr);
    CHECK_AND_RETURN_RET_LOG(ClearContinueCloneTask != nullptr, E_FAIL,
        "Failed to create async task for ClearContinueCloneTask !");
    asyncWorker->AddTask(ClearContinueCloneTask, false);
    return E_SUCCESS;
}

bool MedialibrarySubscriber::IsClearContinueCloneData(const std::string &path)
{
    int64_t cloneTimestamp = MediaFileUtils::GetFileModificationTime(DATA_CLONE_DESCRIPTION_JSON) * SECONDS_TO_MS;
    MEDIA_INFO_LOG("IsClearContinueCloneData fileModificationTime:%{public}" PRId64, cloneTimestamp);
    int64_t curTime = MediaFileUtils::UTCTimeMilliSeconds();
    bool contentNotExistRet = curTime - cloneTimestamp > MS_OF_ONE_DAY;
    std::string content = "";
    bool isContentExist = LoadStringFromFile(path, content) && !content.empty();
    CHECK_AND_RETURN_RET_LOG(isContentExist, contentNotExistRet, "file is empty %{private}s", path.c_str());
    nlohmann::json jsonArray = nlohmann::json::parse(content, nullptr, false);
    CHECK_AND_RETURN_RET_LOG(!jsonArray.is_discarded(), contentNotExistRet, "json array is empty ");
    for (auto& [key, value] : jsonArray.items()) {
        if (key == CLONE_TIME_STAMP && value.is_number_integer()) {
            cloneTimestamp = value.get<int64_t>();
        }
    }
    if (cloneTimestamp == 0) {
        MEDIA_INFO_LOG("not have clone time stamp key");
        cloneTimestamp = MediaFileUtils::GetFileModificationTime(DATA_CLONE_DESCRIPTION_JSON) * SECONDS_TO_MS;
    }
    MEDIA_INFO_LOG("IsClearContinueCloneData cloneTimestamp:%{public}" PRId64, cloneTimestamp);
    return curTime - cloneTimestamp > MS_OF_ONE_DAY;
}

bool MedialibrarySubscriber::TryClearContinueCloneData()
{
    bool isDirExists =
        MediaFileUtils::IsDirExists(CLONE_FOLDER_PATH) || MediaFileUtils::IsDirExists(RESTORE_FOLDER_PATH);
    CHECK_AND_RETURN_RET_LOG(isDirExists, false, "clone foler not exist, return");
    if (!MediaFileUtils::IsFileExists(DATA_CLONE_DESCRIPTION_JSON)) {
        int32_t ret = DoClearContinueCloneData();
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, false, "DoUpdateDirtyForCloudClone failed");
        return true;
    }
    CHECK_AND_RETURN_RET_LOG(IsClearContinueCloneData(DATA_CLONE_DESCRIPTION_JSON), false,
        "not clean continue clone data");
    int32_t taskRet = DoClearContinueCloneData();
    CHECK_AND_RETURN_RET_LOG(taskRet == E_SUCCESS, false, "DoUpdateDirtyForCloudClone failed");
    return true;
}


}  // namespace Media
}  // namespace OHOS
