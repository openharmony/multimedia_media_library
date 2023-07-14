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
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_errno.h"
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
const std::string URI_ARG_OTHER_DELIMITER = "&";
const std::string URI_API_VERSION_STR = std::to_string(static_cast<uint32_t>(MediaLibraryApi::API_10));
const std::string URI_API_VERSION = URI_PARAM_API_VERSION + "=" + URI_API_VERSION_STR;
const std::string URI_AUDIO_STR = AudioColumn::AUDIO_TYPE_URI + SLASH_CHAR;
const std::string URI_FILE_STR = MEDIALIBRARY_TYPE_FILE_URI + SLASH_CHAR;
const std::string URI_PHOTO_STR = PhotoColumn::PHOTO_TYPE_URI + SLASH_CHAR;
const std::string URI_VIDEO_STR = MEDIALIBRARY_TYPE_VIDEO_URI + SLASH_CHAR;
const std::unordered_map<std::string, MediaType> URI_MEDIATYPE_MAP = {
    { URI_AUDIO_STR, MediaType::MEDIA_TYPE_AUDIO },
    { URI_FILE_STR, MediaType::MEDIA_TYPE_FILE },
    { URI_PHOTO_STR, MediaType::MEDIA_TYPE_IMAGE },
    { URI_VIDEO_STR, MediaType::MEDIA_TYPE_VIDEO },
};

std::string GetTableName(const MediaType mediaType)
{
    static const std::map<MediaType, std::string> TYPE_TABLE_MAP = {
        { MediaType::MEDIA_TYPE_AUDIO, AudioColumn::AUDIOS_TABLE },
        { MediaType::MEDIA_TYPE_FILE, MEDIALIBRARY_TABLE },
        { MediaType::MEDIA_TYPE_IMAGE, PhotoColumn::PHOTOS_TABLE },
        { MediaType::MEDIA_TYPE_VIDEO, PhotoColumn::PHOTOS_TABLE },
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

std::string GetOperation(const MediaType mediaType)
{
    static const std::map<MediaType, std::string> TYPE_OPERATION_MAP = {
        { MediaType::MEDIA_TYPE_AUDIO, MEDIA_AUDIOOPRN },
        { MediaType::MEDIA_TYPE_FILE,  MEDIA_DOCUMENTOPRN },
        { MediaType::MEDIA_TYPE_IMAGE, MEDIA_PHOTOOPRN },
        { MediaType::MEDIA_TYPE_VIDEO, MEDIA_PHOTOOPRN },
    };
    std::string operation;
    auto item = TYPE_OPERATION_MAP.find(mediaType);
    if (item != TYPE_OPERATION_MAP.end()) {
        operation = item->second;
    } else {
        MEDIA_ERR_LOG("get operation failed. mediaType:%{public}d", mediaType);
    }
    return operation;
}

bool GetUriInfo(const std::string &uri, std::string &uriId,
    std::string &networkId, MediaType &mediaType)
{
    if (uri.find(ML_FILE_URI_PREFIX) != 0) {
        MEDIA_ERR_LOG("get uri information failed. uri:%{public}s", uri.c_str());
        return false;
    }
    networkId = MediaFileUtils::GetNetworkIdFromUri(uri);
    for (const auto &item : URI_MEDIATYPE_MAP) {
        std::string matchStr = ML_FILE_URI_PREFIX + item.first;
        auto pos = uri.find(matchStr);
        if (pos != 0) {
            continue;
        }
        uriId = uri.substr(matchStr.length());
        mediaType = item.second;
        break;
    }
    if (!IsNumericStr(uriId)) {
        MEDIA_ERR_LOG("get uri information failed. uriId:%{public}s", uriId.c_str());
        return false;
    }
    return true;
}

std::string GetInsertUri(const MediaType mediaType)
{
    std::string uri;
    std::string operation = GetOperation(mediaType);
    if (operation.empty()) {
        MEDIA_ERR_LOG("get insert uri failed. mediaType:%{public}d", mediaType);
        return uri;
    }
    uri = MEDIALIBRARY_DATA_URI;
    uri.append(URI_DELIMITER + operation);
    uri.append(URI_DELIMITER + MEDIA_FILEOPRN_CREATEASSET);
    uri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return uri;
}

std::string GetQueryUri(const MediaType mediaType)
{
    std::string uri;
    std::string tableName = GetTableName(mediaType);
    std::string operation = GetOperation(mediaType);
    if (tableName.empty() || operation.empty()) {
        MEDIA_ERR_LOG("get query uri failed. mediaType:%{public}d", mediaType);
        return uri;
    }
    uri = MEDIALIBRARY_DATA_URI;
    uri.append(URI_DELIMITER + operation);
    uri.append(URI_DELIMITER + tableName);
    uri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return uri;
}

MediaType GetMediaType(const std::string &uri)
{
    std::string id;
    std::string networkId;
    MediaType mediaType = MediaType::MEDIA_TYPE_DEFAULT;
    if (!GetUriInfo(uri, id, networkId, mediaType)) {
        MEDIA_ERR_LOG("get MediaType failed, uri:%{public}s", uri.c_str());
        return MediaType::MEDIA_TYPE_DEFAULT;
    }
    return mediaType;
}

std::string GetOperation(const std::string &uri)
{
    return GetOperation(GetMediaType(uri));
}

std::string GetOpenUri(const std::string &uri)
{
    std::string strUri;
    std::string operation = GetOperation(uri);
    if (operation.empty()) {
        MEDIA_ERR_LOG("get open uri failed. uri:%{public}s", uri.c_str());
        return strUri;
    }
    strUri = uri;
    strUri.append(URI_ARG_FIRST_DELIMITER + URI_API_VERSION);
    return strUri;
}

std::string GetCloseUri(const std::string &uri)
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

int32_t UserFileClientEx::Insert(const MediaType mediaType, const std::string &name)
{
    std::string insertUriStr = GetInsertUri(mediaType);
    if (insertUriStr.empty()) {
        MEDIA_ERR_LOG("insert failed. mediaType:%{public}d, name:%{private}s", mediaType, name.c_str());
        return Media::E_ERR;
    }
    Uri insertUri(insertUriStr);
    DataShare::DataShareValuesBucket values;
    values.Put(MediaColumn::MEDIA_NAME, name);
    values.Put(MediaColumn::MEDIA_TYPE, mediaType);
    MEDIA_INFO_LOG("insert. insertUri:%{public}s, mediaType:%{public}d, name:%{private}s",
        insertUri.ToString().c_str(), mediaType, name.c_str());
    auto ret = UserFileClient::Insert(insertUri, values);
    if (ret <= 0) {
        MEDIA_ERR_LOG("insert failed. ret:%{public}d", ret);
    }
    return ret;
}

int32_t UserFileClientEx::Query(const MediaType mediaType, const std::string &uri,
    std::shared_ptr<FetchResult<FileAsset>> &fetchResult)
{
    fetchResult = nullptr;
    std::string id;
    std::string networkId;
    MediaType parserMediaType = MediaType::MEDIA_TYPE_DEFAULT;
    if ((!uri.empty()) && (!GetUriInfo(uri, id, networkId, parserMediaType))) {
        MEDIA_ERR_LOG("query failed, uri:%{public}s", uri.c_str());
        return Media::E_ERR;
    }
    auto newMediaType = (mediaType == MediaType::MEDIA_TYPE_DEFAULT) ? parserMediaType : mediaType;
    if ((newMediaType != MediaType::MEDIA_TYPE_AUDIO) && (newMediaType != MediaType::MEDIA_TYPE_FILE) &&
        (newMediaType != MediaType::MEDIA_TYPE_IMAGE) && (newMediaType != MediaType::MEDIA_TYPE_VIDEO)) {
        MEDIA_ERR_LOG("query failed, newMediaType:%{public}d, mediaType:%{public}d", newMediaType, mediaType);
        return Media::E_ERR;
    }
    std::string queryUriStr = GetQueryUri(newMediaType);
    if (queryUriStr.empty()) {
        MEDIA_ERR_LOG("query failed. queryUriStr:empty, newMediaType:%{public}d, mediaType:%{public}d",
            newMediaType, mediaType);
        return Media::E_ERR;
    }
    Uri queryUri(queryUriStr);
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, std::to_string(0));
    if (!id.empty()) {
        predicates.And()->EqualTo(MediaColumn::MEDIA_ID, id);
    }
    std::vector<std::string> columns;
    int errCode = 0;
    MEDIA_INFO_LOG("query. queryUri:%{public}s, newMediaType:%{public}d, mediaType:%{public}d, uri:%{public}s, "
        "id:%{public}s", queryUri.ToString().c_str(), newMediaType, mediaType, uri.c_str(), id.c_str());
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
    return GetTableName(mediaType);
}

std::string UserFileClientEx::GetTableNameByUri(const std::string &uri)
{
    return GetTableName(GetMediaType(uri));
}

const std::vector<MediaType> &UserFileClientEx::GetSupportTypes()
{
    static const std::vector<MediaType> SUPPORT_TYPES = {
        MediaType::MEDIA_TYPE_AUDIO,
        MediaType::MEDIA_TYPE_FILE,
        MediaType::MEDIA_TYPE_IMAGE,
        MediaType::MEDIA_TYPE_VIDEO
    };
    return SUPPORT_TYPES;
}
} // namespace MediaTool
} // namespace Media
} // namespace OHOS
