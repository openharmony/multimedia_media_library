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
#define MLOG_TAG "UserFileClientEx"
#include "userfile_client_ex.h"

#include <map>
#include <string>
#include <unordered_map>
#include <unistd.h>

#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "media_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "mimetype_utils.h"
#include "scanner_utils.h"
#include "string_ex.h"
#include "thumbnail_const.h"
#include "uri.h"
#include "userfile_client.h"
#include "userfile_manager_types.h"

using namespace OHOS::DataShare;
namespace OHOS {
namespace Media {
namespace MediaTool {
const std::string URI_DELIMITER = std::string(1, SLASH_CHAR);
const std::string URI_ARG_FIRST_DELIMITER = "?";
const std::string URI_API_VERSION_STR = std::to_string(static_cast<uint32_t>(MediaLibraryApi::API_10));
const std::string URI_API_VERSION = URI_PARAM_API_VERSION + "=" + URI_API_VERSION_STR;

static bool CheckTableName(const std::string &tableName)
{
    static const std::set<std::string> VALID_TABLENAME_WHITELIST = {
        PhotoColumn::PHOTOS_TABLE,
        AudioColumn::AUDIOS_TABLE
    };
    if (tableName.empty()) {
        return false;
    }
    if (VALID_TABLENAME_WHITELIST.find(tableName) == VALID_TABLENAME_WHITELIST.end()) {
        return false;
    }
    return true;
}

static std::string GetOperation(const std::string &tableName)
{
    static const std::map<std::string, std::string> TYPE_OPERATION_MAP = {
        { AudioColumn::AUDIOS_TABLE, MEDIA_AUDIOOPRN },
        { PhotoColumn::PHOTOS_TABLE, MEDIA_PHOTOOPRN }
    };
    std::string operation;
    auto item = TYPE_OPERATION_MAP.find(tableName);
    if (item != TYPE_OPERATION_MAP.end()) {
        operation = item->second;
    } else {
        MEDIA_ERR_LOG("get operation failed. tableName:%{public}s", tableName.c_str());
    }
    return operation;
}

static inline bool GetUriInfo(const std::string &uri, std::string &uriId)
{
    MediaFileUri fileUri(uri);
    if (!fileUri.IsValid()) {
        MEDIA_ERR_LOG("uri %{private}s is invalid", uri.c_str());
        return false;
    }
    uriId = fileUri.GetFileId();
    return true;
}

static inline std::string GetInsertUri(const std::string &tableName)
{
    std::string uri;
    std::string operation = GetOperation(tableName);
    if (operation.empty()) {
        MEDIA_ERR_LOG("get insert uri failed. tableName:%{public}s", tableName.c_str());
        return uri;
    }
    uri = MEDIALIBRARY_DATA_URI;
    uri.append(URI_DELIMITER + operation);
    uri.append(URI_DELIMITER + MEDIA_FILEOPRN_CREATEASSET);
    uri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return uri;
}

static inline std::string GetQueryUri(const std::string &tableName)
{
    std::string uri;
    std::string operation = GetOperation(tableName);
    if (tableName.empty() || operation.empty()) {
        MEDIA_ERR_LOG("get query uri failed. tableName:%{public}s", tableName.c_str());
        return uri;
    }
    uri = MEDIALIBRARY_DATA_URI;
    uri.append(URI_DELIMITER + operation);
    uri.append(URI_DELIMITER + tableName);
    uri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return uri;
}

static inline std::string GetOpenUri(const std::string &uri)
{
    std::string strUri;
    std::string operation = GetOperation(UserFileClientEx::GetTableNameByUri(uri));
    if (operation.empty()) {
        MEDIA_ERR_LOG("get open uri failed. uri:%{public}s", uri.c_str());
        return strUri;
    }
    strUri = uri;
    strUri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return strUri;
}

static inline std::string GetCloseUri(const std::string &uri)
{
    std::string strUri;
    std::string operation = GetOperation(uri);
    if (operation.empty()) {
        MEDIA_ERR_LOG("get close uri failed. uri:%{public}s", uri.c_str());
        return strUri;
    }
    strUri = MEDIALIBRARY_DATA_URI;
    strUri.append(URI_DELIMITER + operation);
    strUri.append(URI_DELIMITER + MEDIA_FILEOPRN_CLOSEASSET);
    strUri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return strUri;
}

bool UserFileClientEx::Init(const sptr<IRemoteObject> &token)
{
    UserFileClient::Init(token);
    return UserFileClient::IsValid();
}

int32_t UserFileClientEx::Insert(const std::string &tableName, const std::string &name)
{
    std::string insertUriStr = GetInsertUri(tableName);
    if (insertUriStr.empty()) {
        MEDIA_ERR_LOG("insert failed. tableName:%{public}s, name:%{private}s", tableName.c_str(),
            name.c_str());
        return Media::E_ERR;
    }
    Uri insertUri(insertUriStr);
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, name);
    string mimeType = MimeTypeUtils::GetMimeTypeFromExtension(ScannerUtils::GetFileExtension(name));
    values.Put(MediaColumn::MEDIA_TYPE, MimeTypeUtils::GetMediaTypeFromMimeType(mimeType));
    MEDIA_INFO_LOG("insert. insertUri:%{public}s, name:%{private}s", insertUri.ToString().c_str(), name.c_str());
    auto ret = UserFileClient::Insert(insertUri, values);
    if (ret <= 0) {
        MEDIA_ERR_LOG("insert failed. ret:%{public}d", ret);
    }
    return ret;
}

int32_t UserFileClientEx::Query(const std::string &tableName, const std::string &uri,
    std::shared_ptr<FetchResult<FileAsset>> &fetchResult)
{
    if (!CheckTableName(tableName)) {
        MEDIA_ERR_LOG("tableName %{public}s is Invalid", tableName.c_str());
        return Media::E_ERR;
    }
    fetchResult = nullptr;
    std::string id;
    if ((!uri.empty()) && (!GetUriInfo(uri, id))) {
        MEDIA_ERR_LOG("query failed, uri:%{public}s", uri.c_str());
        return Media::E_ERR;
    }
    std::string queryUriStr = GetQueryUri(tableName);
    if (queryUriStr.empty()) {
        MEDIA_ERR_LOG("query failed. queryUriStr:empty, tableName:%{public}s", tableName.c_str());
        return Media::E_ERR;
    }
    Uri queryUri(queryUriStr);
    DataShare::DataSharePredicates predicates;
    // Id is empty, meaning get all object from table
    if (!id.empty()) {
        predicates.And()->EqualTo(MediaColumn::MEDIA_ID, id);
    }
    std::vector<std::string> columns;
    int errCode = 0;
    MEDIA_INFO_LOG("query. queryUri:%{public}s, tableName:%{public}s, uri:%{public}s, "
        "id:%{public}s", queryUri.ToString().c_str(), tableName.c_str(), uri.c_str(), id.c_str());
    auto resultSet = UserFileClient::Query(queryUri, predicates, columns, errCode);
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("query failed. resultSet:null, errCode:%{public}d.", errCode);
        return ((errCode == Media::E_OK) ? Media::E_OK : Media::E_ERR);
    }
    if (errCode != Media::E_OK) {
        MEDIA_ERR_LOG("query failed. errCode:%{public}d.", errCode);
        resultSet->Close();
        return Media::E_ERR;
    }
    fetchResult = std::make_shared<FetchResult<FileAsset>>(resultSet);
    fetchResult->SetResultNapiType(ResultNapiType::TYPE_USERFILE_MGR);
    return Media::E_OK;
}

int UserFileClientEx::Open(const std::string &uri, const std::string &mode)
{
    std::string openUriStr = GetOpenUri(uri);
    if (openUriStr.empty()) {
        return Media::E_FAIL;
    }
    Uri openUri(openUriStr);
    MEDIA_INFO_LOG("open. openUri:%{public}s, mode:%{public}s", openUri.ToString().c_str(), mode.c_str());
    return UserFileClient::OpenFile(openUri, mode);
}

int UserFileClientEx::Close(const std::string &uri, const int fileFd, const std::string &mode,
    bool isCreateThumbSync)
{
    if (!UserFileClient::IsValid()) {
        MEDIA_ERR_LOG("close failed. helper:null. uri:%{public}s, fileFd:%{public}d, mode:%{public}s",
            uri.c_str(), fileFd, mode.c_str());
        return Media::E_FAIL;
    }
    if (close(fileFd) != E_SUCCESS) {
        MEDIA_ERR_LOG("close failed. uri:%{public}s, fileFd:%{public}d, mode:%{public}s",
            uri.c_str(), fileFd, mode.c_str());
        return Media::E_FAIL;
    }
    if (mode == Media::MEDIA_FILEMODE_READONLY) {
        return Media::E_OK;
    }
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);
    if (isCreateThumbSync) {
        valuesBucket.Put(CLOSE_CREATE_THUMB_STATUS, CREATE_THUMB_SYNC_STATUS);
    }
    std::string closeUriStr = GetCloseUri(uri);
    if (closeUriStr.empty()) {
        MEDIA_ERR_LOG("get close uri failed. uri:%{public}s", uri.c_str());
        return Media::E_FAIL;
    }
    Uri closeUri(closeUriStr);
    MEDIA_INFO_LOG("close. closeUri:%{public}s, uri:%{public}s", closeUri.ToString().c_str(), uri.c_str());
    auto ret = UserFileClient::Insert(closeUri, valuesBucket);
    if (ret == Media::E_FAIL) {
        MEDIA_ERR_LOG("close the file failed. ret:%{public}d, closeUri:%{public}s, uri:%{public}s",
            ret, closeUri.ToString().c_str(), uri.c_str());
    }
    return ret;
}

std::string UserFileClientEx::GetTableNameByMediaType(const MediaType mediaType)
{
    static const std::map<MediaType, std::string> TYPE_TABLE_MAP = {
        { MediaType::MEDIA_TYPE_AUDIO, AudioColumn::AUDIOS_TABLE },
        { MediaType::MEDIA_TYPE_IMAGE, PhotoColumn::PHOTOS_TABLE },
        { MediaType::MEDIA_TYPE_VIDEO, PhotoColumn::PHOTOS_TABLE },
        { MediaType::MEDIA_TYPE_PHOTO, PhotoColumn::PHOTOS_TABLE }
    };
    std::string tableName;
    auto item = TYPE_TABLE_MAP.find(mediaType);
    if (item != TYPE_TABLE_MAP.end()) {
        tableName = item->second;
    } else {
        MEDIA_ERR_LOG("get table name failed. mediaType:%{public}d", mediaType);
    }
    return tableName;
}

std::string UserFileClientEx::GetTableNameByUri(const std::string &uri)
{
    MediaFileUri fileUri(uri);
    if (!fileUri.IsValid()) {
        MEDIA_ERR_LOG("uri %{private}s is invalid", uri.c_str());
        return "";
    }
    return fileUri.GetTableName();
}

const std::vector<MediaType> &UserFileClientEx::GetSupportTypes()
{
    static const std::vector<MediaType> SUPPORT_TYPES = {
        MediaType::MEDIA_TYPE_AUDIO,
        MediaType::MEDIA_TYPE_IMAGE,
        MediaType::MEDIA_TYPE_VIDEO
    };
    return SUPPORT_TYPES;
}

const std::vector<std::string> &UserFileClientEx::GetSupportTables()
{
    static const std::vector<std::string> SUPPORT_TABLES = {
        PhotoColumn::PHOTOS_TABLE,
        AudioColumn::AUDIOS_TABLE
    };
    return SUPPORT_TABLES;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
