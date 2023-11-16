/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_formmap_operations.h"

#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <fcntl.h>

#include "abs_shared_result_set.h"
#include "file_ex.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_rdbstore.h"
#include "rdb_predicates.h"
#include "result_set_utils.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "uri.h"
#include "userfile_manager_types.h"
#include "value_object.h"
#include "values_bucket.h"
#include "image_type.h"
#include "datashare_helper.h"
#include "unique_fd.h"
#include "medialibrary_data_manager.h"
#include "thumbnail_utils.h"
#include "ithumbnail_helper.h"
#include "form_map.h"

using namespace OHOS::DataShare;
using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::RdbDataShareAdapter;

namespace OHOS {
namespace Media {
std::mutex MediaLibraryFormMapOperations::mutex_;
static bool isHaveEmptyUri = false;
static string MEDIA_LIBRARY_PROXY_URI = "datashareproxy://com.ohos.medialibrary.medialibrarydata/image_data";

bool MediaLibraryFormMapOperations::GetFormIdWithEmptyUriState()
{
    return isHaveEmptyUri;
}

static void ReadThumbnailFile(const string &path, vector<uint8_t> &buffer)
{
    string thumbnailFileName = GetThumbnailPath(path, THUMBNAIL_LCD_SUFFIX);
    auto fd = open(thumbnailFileName.c_str(), O_RDONLY);
    UniqueFd uniqueFd(fd);
    struct stat statInfo;
    if (fstat(uniqueFd.Get(), &statInfo) == E_ERR) {
        return ;
    }
    buffer.reserve(statInfo.st_size);
    uint8_t tempBuffer[statInfo.st_size];
    ssize_t bytes = read(uniqueFd.Get(), tempBuffer, statInfo.st_size);
    if (bytes < 0) {
        MEDIA_ERR_LOG("read file failed!");
        return ;
    }
    buffer.assign(tempBuffer, tempBuffer + statInfo.st_size);
}

string MediaLibraryFormMapOperations::GetUriByFileId(const int32_t &fileId, const string &path)
{
    MediaLibraryCommand queryCmd(OperationObject::UFM_PHOTO, OperationType::QUERY);
    queryCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, to_string(fileId));
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return "";
    }
    vector<string> columns = {
        MEDIA_DATA_DB_ID, MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_NAME
    };
    auto queryResult = uniStore->Query(queryCmd, columns);
    if (queryResult == nullptr || queryResult->GoToFirstRow() != NativeRdb::E_OK) {
        return "";
    }
    string displayName = GetStringVal(MEDIA_DATA_DB_NAME, queryResult);
    int32_t mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, queryResult);
    if (mediaType != MEDIA_TYPE_IMAGE) {
        return "";
    }
    string extraUri = MediaFileUtils::GetExtraUri(displayName, path, false);
    return MediaFileUri(MediaType(mediaType), ToString(fileId), "", MEDIA_API_VERSION_V10,  extraUri).ToString();
}

string MediaLibraryFormMapOperations::CheckAndGetNewUri(const string &uri, bool &isNext)
{
    if (uri.empty()) {
        return "";
    }
    MediaFileUri fileUri = MediaFileUri(uri);
    string tempFileId = fileUri.GetFileId();
    int fileId = 0;
    if (!StrToInt(tempFileId, fileId)) {
        return "";
    }

    MediaLibraryCommand queryCmd(OperationObject::UFM_PHOTO, OperationType::QUERY);
    if (isNext) {
        queryCmd.GetAbsRdbPredicates()->GreaterThan(MEDIA_DATA_DB_ID, fileId);
    } else {
        queryCmd.GetAbsRdbPredicates()->LessThan(MEDIA_DATA_DB_ID, fileId);
    }
    queryCmd.GetAbsRdbPredicates()->And()->EqualTo(MEDIA_DATA_DB_DATE_TRASHED, 0);

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return "";
    }
    vector<string> columns = {
        MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_NAME
    };
    auto queryResult = uniStore->Query(queryCmd, columns);
    if (queryResult == nullptr) {
        MEDIA_ERR_LOG("Can not get next uri");
        return "";
    }
    if (isNext) {
        queryResult->GoToFirstRow();
    } else {
        queryResult->GoToLastRow();
    }
    string path = GetStringVal(MEDIA_DATA_DB_FILE_PATH, queryResult);
    if (path.empty()) {
        return "";
    }
    string displayName = GetStringVal(MEDIA_DATA_DB_NAME, queryResult);
    int32_t mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, queryResult);
    int32_t nextFileId = GetInt32Val(MEDIA_DATA_DB_ID, queryResult);
    string extraUri = MediaFileUtils::GetExtraUri(displayName, path, false);
    return MediaFileUri(MediaType(mediaType), ToString(nextFileId), "", MEDIA_API_VERSION_V10,  extraUri).ToString();
}

void MediaLibraryFormMapOperations::GetFormMapFormId(const string &uri, vector<int64_t> &formIds)
{
    lock_guard<mutex> lock(mutex_);
    MediaLibraryCommand queryFormMapCmd(OperationObject::PAH_FORM_MAP, OperationType::QUERY);
    queryFormMapCmd.GetAbsRdbPredicates()->EqualTo(FormMap::FORMMAP_URI, uri);

    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return;
    }
    vector<string> columns = {FormMap::FORMMAP_FORM_ID, FormMap::FORMMAP_URI};
    auto queryResult = uniStore->Query(queryFormMapCmd, columns);
    if (queryResult == nullptr) {
        MEDIA_ERR_LOG("Failed to query form id!");
        return;
    }
    while (queryResult->GoToNextRow() == NativeRdb::E_OK) {
        string tempFormId = GetStringVal(FormMap::FORMMAP_FORM_ID, queryResult);
        if (tempFormId.empty()) {
            MEDIA_WARN_LOG("Failed to get form id from result!");
            continue;
        }
        if (GetStringVal(FormMap::FORMMAP_URI, queryResult) == uri) {
            int64_t formId = std::stoll(tempFormId);
            formIds.push_back(formId);
        }
    }
}

static string GetFilePathById(const string &fileId)
{
    MediaLibraryCommand queryCmd(OperationObject::UFM_PHOTO, OperationType::QUERY);
    queryCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, fileId);
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return "";
    }
    vector<string> columns = {
        MEDIA_DATA_DB_ID, MEDIA_DATA_DB_FILE_PATH
    };
    auto queryResult = uniStore->Query(queryCmd, columns);
    if (queryResult == nullptr || queryResult->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Get path by Id failed , id is %{private}s", fileId.c_str());
        return "";
    }
    return GetStringVal(MEDIA_DATA_DB_FILE_PATH, queryResult);
}

int MediaLibraryFormMapOperations::ModifyFormMapMassage(const string &uri, int64_t &formId)
{
    lock_guard<mutex> lock(mutex_);
    string NewUri = uri;
    if (!uri.empty()) {
        int pos = uri.find("?");
        if (pos > 0) {
            NewUri = uri.substr(0, pos);
        }
    }
    ValuesBucket value;
    value.PutString(FormMap::FORMMAP_URI, NewUri);

    RdbPredicates predicates(FormMap::FORM_MAP_TABLE);
    predicates.And()->EqualTo(FormMap::FORMMAP_FORM_ID, std::to_string(formId));
    return MediaLibraryRdbStore::Update(value, predicates);
}

void MediaLibraryFormMapOperations::PublishedChange(const string newUri, vector<int64_t> &formIds)
{
    CreateOptions options;
    options.enabled_ = true;
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(MEDIA_LIBRARY_PROXY_URI, options);
    if (dataShareHelper == nullptr) {
        MEDIA_ERR_LOG("dataShareHelper is nullptr");
        return;
    }
    Data data;
    vector<uint8_t> buffer;
    PublishedDataItem::DataType tempData;
    if (newUri.empty()) {
        for (auto &formId : formIds) {
            data.datas_.emplace_back(PublishedDataItem(MEDIA_LIBRARY_PROXY_URI, formId, tempData));
            std::vector<OperationResult> results = dataShareHelper->Publish(data, BUNDLE_NAME);
            MEDIA_INFO_LOG("Published uri is %{private}s!", MEDIA_LIBRARY_PROXY_URI.c_str());
            MEDIA_INFO_LOG("Published formId is %{private}lld!", formId);
            MEDIA_INFO_LOG("Published size of value is %{private}d!", buffer.size());
            if (MediaLibraryFormMapOperations::ModifyFormMapMassage(newUri, formId) < 0) {
                MEDIA_ERR_LOG("Modify FormMap massage err!, uri is %{private}s, formId is %{private}lld",
                    newUri.c_str(), formId);
            }
            isHaveEmptyUri = true;
        }
    } else {
        MediaFileUri fileUri = MediaFileUri(newUri);
        ThumbnailWait thumbnailWait(false);
        thumbnailWait.CheckAndWait(fileUri.GetFileId(), true);
        string filePath = GetFilePathById(fileUri.GetFileId());
        int32_t type = MediaFileUtils::GetMediaType(filePath);
        if (MEDIA_TYPE_IMAGE == MediaType(type)) {
            ReadThumbnailFile(filePath, buffer);
            tempData = buffer;
            for (auto &formId : formIds) {
                data.datas_.emplace_back(PublishedDataItem(MEDIA_LIBRARY_PROXY_URI, formId, tempData));
                std::vector<OperationResult> results = dataShareHelper->Publish(data, BUNDLE_NAME);
                MEDIA_INFO_LOG("Published uri is %{private}s!", MEDIA_LIBRARY_PROXY_URI.c_str());
                MEDIA_INFO_LOG("Published formId is %{private}lld!", formId);
                MEDIA_INFO_LOG("Published size of value is %{private}d!", buffer.size());
                if (MediaLibraryFormMapOperations::ModifyFormMapMassage(newUri, formId) < 0) {
                    MEDIA_ERR_LOG("Modify FormMap massage err!, uri is %{private}s, formId is %{private}lld",
                        newUri.c_str(), formId);
                }
                isHaveEmptyUri = false;
            }
        }
    }
}

void MediaLibraryFormMapOperations::DoPublishedChange(const string &uri)
{
    vector<int64_t> formIds;
    string newUri;
    bool isNext = true;
    MediaLibraryFormMapOperations::GetFormMapFormId(uri, formIds);
    if (!formIds.empty()) {
        newUri = MediaLibraryFormMapOperations::CheckAndGetNewUri(uri, isNext);
        if (newUri.empty()) {
            isNext = false;
            newUri = MediaLibraryFormMapOperations::CheckAndGetNewUri(uri, isNext);
        }
        MediaLibraryFormMapOperations::PublishedChange(newUri, formIds);
    }
}

int32_t MediaLibraryFormMapOperations::RemoveFormIdOperations(RdbPredicates &predicates)
{
    lock_guard<mutex> lock(mutex_);
    return MediaLibraryRdbStore::Delete(predicates);
}

static string GetStringObject(MediaLibraryCommand &cmd, const string &columnName)
{
    ValueObject valueObject;
    ValuesBucket values = cmd.GetValueBucket();
    string value;
    if (values.GetObject(columnName, valueObject)) {
        valueObject.GetString(value);
        return value;
    }
    return "";
}

bool MediaLibraryFormMapOperations::CheckQueryIsInDb(const OperationObject &operationObject, const string &queryId)
{
    lock_guard<mutex> lock(mutex_);
    MediaLibraryCommand queryFormMapCmd(operationObject, OperationType::QUERY);
    vector<string> columns;
    if (operationObject == OperationObject::PAH_FORM_MAP) {
        queryFormMapCmd.GetAbsRdbPredicates()->EqualTo(FormMap::FORMMAP_FORM_ID, queryId);
        columns = { FormMap::FORMMAP_FORM_ID };
    } else if (operationObject == OperationObject::UFM_PHOTO) {
        queryFormMapCmd.GetAbsRdbPredicates()->EqualTo(MEDIA_DATA_DB_ID, queryId);
        columns = { MEDIA_DATA_DB_ID };
    }
    auto uniStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (uniStore == nullptr) {
        MEDIA_ERR_LOG("UniStore is nullptr");
        return false;
    }
    auto queryResultSet = uniStore->Query(queryFormMapCmd, columns);
    if (queryResultSet != nullptr) {
        if (queryResultSet->GoToFirstRow() == NativeRdb::E_OK) {
            MEDIA_INFO_LOG("The id queried already exists!");
            return true;
        }
    }
    return false;
}

int32_t MediaLibraryFormMapOperations::HandleStoreFormIdOperation(MediaLibraryCommand &cmd)
{
    string formId = GetStringObject(cmd, FormMap::FORMMAP_FORM_ID);
    if (formId.empty()) {
        MEDIA_ERR_LOG("GetObject failed");
        return E_GET_PRAMS_FAIL;
    }
    string uri = GetStringObject(cmd, FormMap::FORMMAP_URI);
    ValuesBucket value;
    value.PutString(FormMap::FORMMAP_URI, uri);

    if (uri.empty()) {
        isHaveEmptyUri = true;
    } else {
        MediaFileUri mediaUri(uri);
        string fileId = mediaUri.GetFileId();
        CHECK_AND_RETURN_RET_LOG(MediaLibraryFormMapOperations::CheckQueryIsInDb(OperationObject::UFM_PHOTO, fileId),
            E_GET_PRAMS_FAIL, "the fileId is not exist");
    }
    if (MediaLibraryFormMapOperations::CheckQueryIsInDb(OperationObject::PAH_FORM_MAP, formId)) {
        lock_guard<mutex> lock(mutex_);
        RdbPredicates predicates(FormMap::FORM_MAP_TABLE);
        predicates.EqualTo(FormMap::FORMMAP_FORM_ID, formId);
        return MediaLibraryRdbStore::Update(value, predicates);
    }

    auto rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStoreRaw();
    if (rdbStore == nullptr) {
        return E_HAS_DB_ERROR;
    }
    int64_t outRowId = -1;
    lock_guard<mutex> lock(mutex_);
    int32_t errCode = rdbStore->Insert(cmd, outRowId);
    if (errCode != NativeRdb::E_OK || outRowId < 0) {
        MEDIA_ERR_LOG("Insert into db failed, errCode = %{public}d", errCode);
        return E_HAS_DB_ERROR;
    }
    return static_cast<int32_t>(outRowId);
}
} // namespace Media
} // namespace OHOS