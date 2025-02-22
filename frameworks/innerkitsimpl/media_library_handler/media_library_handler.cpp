/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryHandler"

#include "media_library_handler.h"

#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <vector>
#include <securec.h>
#include "accesstoken_kit.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "userfilemgr_uri.h"
#include "rdb_errno.h"
#include "os_account_manager.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;

bool GetDataUris(const vector<string> &uris, vector<string> &dataUris)
{
    auto handler = OHOS::Media::MediaLibraryHandler::GetMediaLibraryHandler();
    handler->InitMediaLibraryHandler();
    int32_t ret = handler->GetDataUris(uris, dataUris);
    if (ret != OHOS::Media::E_SUCCESS) {
        MEDIA_ERR_LOG("Failed to GetDataPath: %{public}d", ret);
        return false;
    }
    return true;
}

extern "C" {
void ConvertFileUriToMntPath(const vector<string> &uris, vector<string> &results)
{
    int32_t userId = 0;
    OHOS::ErrCode errCode = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (errCode != OHOS::ERR_OK) {
        MEDIA_ERR_LOG("GetForegroundOsAccountLocalId fail, code %{public}d", errCode);
        results.clear();
        return;
    }

    vector<string> dataUris;
    if (!GetDataUris(uris, dataUris)) {
        results.clear();
        return;
    }
    results.clear();
    for (vector<string>::size_type i = 0; i < dataUris.size(); i++) {
        if (dataUris[i].empty()) {
            results.clear();
            return;
        }
        std::ostringstream oss;
        oss << OHOS::Media::HMDFS << userId << OHOS::Media::CLOUD_MERGE_VIEW << dataUris[i];
        results.emplace_back(oss.str());
    }
}
}

namespace OHOS {
namespace Media {
shared_ptr<DataShare::DataShareHelper> MediaLibraryHandler::sDataShareHelper_ = nullptr;
sptr<IRemoteObject> MediaLibraryHandler::token_ = nullptr;

MediaLibraryHandler *MediaLibraryHandler::GetMediaLibraryHandler()
{
    static MediaLibraryHandler mediaLibHandler;
    return &mediaLibHandler;
}

sptr<IRemoteObject> MediaLibraryHandler::InitToken()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_ERR_LOG("get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObj == nullptr) {
        MEDIA_ERR_LOG("GetSystemAbility Service failed.");
        return nullptr;
    }
    return remoteObj;
}

void MediaLibraryHandler::InitMediaLibraryHandler()
{
    if (sDataShareHelper_ == nullptr) {
        token_ = InitToken();
        if (token_ != nullptr) {
            sDataShareHelper_ = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
        }
    }
}

std::shared_ptr<DataShareResultSet> GetResultSetFromPhotos(const string &columnName, const vector<string> &values,
    vector<string> &columns, shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    Uri queryUri(PAH_QUERY_CONVERT_PHOTOS);
    DataSharePredicates predicates;
    predicates.In(columnName, values);
    DatashareBusinessError businessError;
    return dataShareHelper->Query(queryUri, predicates, columns, &businessError);
}

inline bool StartWith(const string &str, const string &prefix)
{
    return str.compare(0, prefix.size(), prefix) == 0;
}

bool GetFileIds(const vector<string> &uris, vector<string> &results, vector<string> &realIds)
{
    for (vector<string>::size_type i = 0; i < uris.size(); i++) {
        string uri = uris[i];
        if (!StartWith(uri, MEDIA_PHOTO_URI)) {
            MEDIA_ERR_LOG("%{private}s fails to start with: %{private}s", uri.c_str(), MEDIA_PHOTO_URI.c_str());
            return false;
        }

        size_t size_media_photo = MEDIA_PHOTO_URI.size();
        size_t index = uri.find("/", size_media_photo);
        if (index == string::npos) {
            MEDIA_ERR_LOG("failed to find /, path is %{private}s", uri.c_str());
            return false;
        }

        string fileId = uri.substr(size_media_photo, index - size_media_photo);
        if (!all_of(fileId.begin(), fileId.end(), ::isdigit)) {
            MEDIA_ERR_LOG("fileId is not digit, fileId is %{private}s", fileId.c_str());
            return false;
        }
        results.push_back(fileId);

        auto it = std::find(realIds.begin(), realIds.end(), fileId);
        if (it == realIds.end()) {
            realIds.push_back(fileId);
        }
    }
    return true;
}

int32_t MediaLibraryHandler::GetDataUris(const vector<string> &uris, vector<string> &dataUris)
{
    if (uris.empty()) {
        MEDIA_ERR_LOG("uris is empty");
        return E_FAIL;
    }
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return E_FAIL;
    }

    vector<string> fileIds;
    vector<string> realIds;
    if (!GetFileIds(uris, fileIds, realIds)) {
        return E_FAIL;
    }

    vector<string> columns = {MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH};
    auto resultSet = GetResultSetFromPhotos(MEDIA_DATA_DB_ID, realIds, columns, sDataShareHelper_);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("resultSet is nullptr");
        return E_FAIL;
    }
    if (ProcessResultSet(resultSet, dataUris, fileIds) != E_SUCCESS) {
        resultSet->Close();
        return E_FAIL;
    }
    resultSet->Close();
    return E_SUCCESS;
}

int32_t MediaLibraryHandler::ProcessResultSet(shared_ptr<DataShareResultSet> &resultSet,
                                              vector<string> &dataUris, vector<string> &fileIds)
{
    int32_t row = 0;
    if (CheckResultSet(resultSet, row) != E_SUCCESS) {
        return E_FAIL;
    }

    dataUris = vector<string>(fileIds.size());

    int32_t count = 0;
    while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
        string fileId;
        string path;
        if (resultSet->GetString(0, fileId) != NativeRdb::E_OK) {
            return E_FAIL;
        }

        if (resultSet->GetString(1, path) != NativeRdb::E_OK) {
            return E_FAIL;
        }

        if (!StartWith(path, ROOT_MEDIA_DIR)) {
            MEDIA_ERR_LOG("%{private}s fails to start with: %{private}s", path.c_str(), ROOT_MEDIA_DIR.c_str());
            return E_FAIL;
        }

        for (vector<string>::size_type j = 0; j < dataUris.size(); j++) {
            if (dataUris[j].empty() && fileIds[j] == fileId) {
                dataUris[j] = path.substr(ROOT_MEDIA_DIR.length());
                count++;
            }
        }
    }

    if (count != dataUris.size()) {
        return E_FAIL;
    }
    return E_SUCCESS;
}

int32_t MediaLibraryHandler::CheckResultSet(shared_ptr<DataShareResultSet> &resultSet, int32_t &row)
{
    auto ret = resultSet->GetRowCount(row);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to get resultset row count, ret: %{public}d", ret);
        return ret;
    }
    if (row <= 0) {
        MEDIA_ERR_LOG("Failed to get count, count: %{public}d", row);
        return E_FAIL;
    }
    return E_SUCCESS;
}
} // namespace Media
} // namespace OHOS
