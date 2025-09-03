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
#include "image_type.h"

#define MLOG_TAG "MediaLibraryManager"

#include "media_library_manager.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "accesstoken_kit.h"
#include "album_asset.h"
#include "datashare_abs_result_set.h"
#include "datashare_predicates.h"
#include "directory_ex.h"
#include "fetch_result.h"
#include "file_asset.h"
#include "file_uri.h"
#include "image_source.h"
#include "iservice_registry.h"
#include "media_asset_rdbstore.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_kvstore_manager.h"
#include "medialibrary_tracer.h"
#include "medialibrary_type_const.h"
#include "media_app_uri_permission_column.h"
#include "media_app_uri_sensitive_column.h"
#include "media_library_tab_old_photos_client.h"
#include "moving_photo_file_utils.h"
#include "post_proc.h"
#include "permission_utils.h"
#include "result_set_utils.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "thumbnail_const.h"
#include "unique_fd.h"
#include "userfilemgr_uri.h"
#include "data_secondary_directory_uri.h"
#include "medialibrary_business_code.h"
#include "user_inner_ipc_client.h"
#include "photo_album_column.h"
#include "add_visit_count_vo.h"
#include "create_asset_vo.h"
#include "get_result_set_from_db_vo.h"
#include "get_moving_photo_date_modified_vo.h"
#include "get_uri_from_filepath_vo.h"
#include "get_filepath_from_uri_vo.h"
#include "close_asset_vo.h"
#include "get_result_set_from_photos_extend_vo.h"
#include "get_albums_lpath_by_ids_vo.h"
#include "query_albums_vo.h"
#include "retain_cloud_media_asset_vo.h"

#ifdef IMAGE_PURGEABLE_PIXELMAP
#include "purgeable_pixelmap_builder.h"
#endif

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
shared_ptr<DataShare::DataShareHelper> MediaLibraryManager::sDataShareHelper_ = nullptr;
sptr<IRemoteObject> MediaLibraryManager::token_ = nullptr;
constexpr int32_t DEFAULT_THUMBNAIL_SIZE = 256;
constexpr int32_t MAX_DEFAULT_THUMBNAIL_SIZE = 768;
constexpr int32_t DEFAULT_MONTH_THUMBNAIL_SIZE = 128;
constexpr int32_t DEFAULT_YEAR_THUMBNAIL_SIZE = 64;
constexpr int32_t URI_MAX_SIZE = 1000;

const std::string MULTI_USER_URI_FLAG = "user=";

struct UriParams {
    string path;
    string fileUri;
    Size size;
    bool isAstc;
    DecodeDynamicRange dynamicRange;
    string user;
};

MediaLibraryManager *MediaLibraryManager::GetMediaLibraryManager()
{
    static MediaLibraryManager mediaLibMgr;
    return &mediaLibMgr;
}

void MediaLibraryManager::InitMediaLibraryManager(const sptr<IRemoteObject> &token)
{
    token_ = token;
    CHECK_AND_EXECUTE(sDataShareHelper_ != nullptr,
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI));
}

sptr<IRemoteObject> MediaLibraryManager::InitToken()
{
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_AND_RETURN_RET_LOG(saManager != nullptr, nullptr, "get system ability mgr failed.");
    auto remoteObj = saManager->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    CHECK_AND_RETURN_RET_LOG(remoteObj != nullptr, nullptr, "GetSystemAbility Service failed.");
    return remoteObj;
}

void MediaLibraryManager::InitMediaLibraryManager()
{
    token_ = InitToken();
    if (sDataShareHelper_ == nullptr && token_ != nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    }
}

string MediaLibraryManager::CreateAsset(const string &displayName)
{
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    if (dataShareHelper == nullptr || displayName.empty()) {
        MEDIA_ERR_LOG("Failed to create Asset, datashareHelper is nullptr");
        return "";
    }
    MediaType mediaType = MediaFileUtils::GetMediaType(displayName);
    CHECK_AND_RETURN_RET_LOG((mediaType == MEDIA_TYPE_IMAGE || mediaType == MEDIA_TYPE_VIDEO),
        "", "Failed to create Asset, invalid file type.");
    CreateAssetReqBody reqBody;
    reqBody.mediaType = static_cast<int32_t>(mediaType);
    reqBody.photoSubtype = static_cast<int32_t>(PhotoSubType::DEFAULT);
    reqBody.displayName = displayName;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CREATE_ASSET);
    CreateAssetRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    if (errCode != 0) {
        MEDIA_ERR_LOG("after IPC::UserDefineIPCClient().Call, errCode: %{public}d.", errCode);
        return "";
    }
    string outUri = respBody.outUri;
    return outUri;
}

static bool CheckUri(string &uri)
{
    if (uri.find("../") != string::npos) {
        return false;
    }
    string uriprex = "file://media";
    return uri.substr(0, uriprex.size()) == uriprex;
}

static bool CheckPhotoUri(const string &uri)
{
    if (uri.find("../") != string::npos) {
        return false;
    }
    string photoUriPrefix = "file://media/Photo/";
    return MediaFileUtils::StartsWith(uri, photoUriPrefix);
}

int32_t MediaLibraryManager::OpenAsset(string &uri, const string openMode)
{
    CHECK_AND_RETURN_RET(!openMode.empty(), E_ERR);
    CHECK_AND_RETURN_RET_LOG(CheckUri(uri), E_ERR, "invalid uri");
    string originOpenMode = openMode;
    std::transform(originOpenMode.begin(), originOpenMode.end(),
        originOpenMode.begin(), [](unsigned char c) {return std::tolower(c);});
    if (!MEDIA_OPEN_MODES.count(originOpenMode)) {
        return E_ERR;
    }

    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to open Asset, datashareHelper is nullptr");
        return E_ERR;
    }
    Uri openUri(uri);
    return sDataShareHelper_->OpenFile(openUri, openMode);
}

int32_t MediaLibraryManager::CloseAsset(const string &uri, const int32_t fd)
{
    int32_t retVal = E_FAIL;

    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    if (dataShareHelper != nullptr) {
        if (close(fd) == E_SUCCESS) {
            CloseAssetReqBody reqBody;
            reqBody.uri = uri;
            retVal = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(
                static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_CLOSE_ASSET), reqBody);
        }

        if (retVal == E_FAIL) {
            MEDIA_ERR_LOG("Failed to close the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::GetAstcYearAndMonth(const std::vector<string> &uris)
{
    if ((uris.empty()) || (uris.size() > URI_MAX_SIZE)) {
        MEDIA_ERR_LOG("Failed to check uri size");
        return E_ERR;
    }

    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Failed to GetAstcYearAndMonth, datashareHelper is nullptr");
        return E_ERR;
    }
    string abilityUri = MEDIALIBRARY_DATA_URI;
    Uri astcUri(abilityUri + "/" + MTH_AND_YEAR_ASTC + "/" + MTH_AND_YEAR_ASTC);
    DataShareValuesBucket bucket;
    for (auto uri : uris) {
        bucket.Put(uri, false);
    }
    vector<DataShareValuesBucket> values;
    values.emplace_back(bucket);
    return sDataShareHelper_->BatchInsert(astcUri, values);
}

int32_t MediaLibraryManager::QueryTotalSize(MediaVolume &outMediaVolume)
{
    auto dataShareHelper = DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_FAIL, "dataShareHelper is null");
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN_QUERYVOLUME + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    DataSharePredicates predicates;
    auto queryResultSet = dataShareHelper->Query(uri, predicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, E_FAIL, "queryResultSet is null!");
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, E_HAS_DB_ERROR, "get rdbstore failed");
    MEDIA_INFO_LOG("count = %{public}d", (int)count);

    if (count >= 0) {
        int thumbnailType = -1;
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int mediatype = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE,
                queryResultSet, TYPE_INT32));
            int64_t size = get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_SIZE,
                queryResultSet, TYPE_INT64));
            MEDIA_INFO_LOG("media_type: %{public}d, size: %{public}lld", mediatype, static_cast<long long>(size));
            if (mediatype == MEDIA_TYPE_IMAGE || mediatype == thumbnailType) {
                outMediaVolume.SetSize(MEDIA_TYPE_IMAGE, outMediaVolume.GetImagesSize() + size);
            } else {
                outMediaVolume.SetSize(mediatype, size);
            }
        }
    }
    MEDIA_INFO_LOG("Size: Files:%{public}lld, Videos:%{public}lld, Images:%{public}lld, Audio:%{public}lld",
        static_cast<long long>(outMediaVolume.GetFilesSize()),
        static_cast<long long>(outMediaVolume.GetVideosSize()),
        static_cast<long long>(outMediaVolume.GetImagesSize()),
        static_cast<long long>(outMediaVolume.GetAudiosSize())
    );
    return E_SUCCESS;
}

std::shared_ptr<DataShareResultSet> GetResultSetFromPhotos(const string &value, vector<string> &columns,
    sptr<IRemoteObject> &token, shared_ptr<DataShare::DataShareHelper> &dataShareHelper)
{
    CHECK_AND_RETURN_RET_LOG(CheckPhotoUri(value), nullptr, "Failed to check invalid uri: %{public}s", value.c_str());
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "datashareHelper is nullptr");

    GetResultSetFromPhotosExtendReqBody reqBody;
    reqBody.value = value;
    reqBody.columns = columns;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_RESULT_SET_FROM_PHOTOS);
    GetResultSetFromDbRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("errCode: %{public}d", errCode);
        return nullptr;
    }
    return respBody.resultSet;
}

std::shared_ptr<DataShareResultSet> MediaLibraryManager::GetResultSetFromDb(string columnName, const string &value,
    vector<string> &columns)
{
    if (columnName == MEDIA_DATA_DB_URI) {
        auto resultSet = GetResultSetFromPhotos(value, columns, token_, sDataShareHelper_);
        if (resultSet == nullptr) {
            MEDIA_ERR_LOG("resultset is null, reconnect and retry");
            shared_ptr<DataShare::DataShareHelper> dataShareHelper =
                DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
            return GetResultSetFromPhotos(value, columns, token_, dataShareHelper);
        } else {
            return resultSet;
        }
    }

    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "dataShareHelper is null");

    GetResultSetFromDbReqBody reqBody;
    reqBody.columnName = columnName;
    reqBody.value = value;
    reqBody.columns = columns;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_RESULT_SET_FROM_DB);
    GetResultSetFromDbRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    if (errCode != 0) {
        MEDIA_ERR_LOG("after IPC::UserDefineIPCClient().Call, errCode: %{public}d.", errCode);
        return nullptr;
    }
    return respBody.resultSet;
}

static int32_t SolvePath(const string &filePath, string &tempPath, string &userId)
{
    CHECK_AND_RETURN_RET(!filePath.empty(), E_INVALID_PATH);
    string prePath = PRE_PATH_VALUES;
    if (filePath.find(prePath) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string postpath = filePath.substr(prePath.length());
    auto pos = postpath.find('/');
    CHECK_AND_RETURN_RET(pos != string::npos, E_INVALID_ARGUMENTS);
    userId = postpath.substr(0, pos);
    postpath = postpath.substr(pos + 1);
    tempPath = prePath + postpath;
    return E_SUCCESS;
}

int32_t MediaLibraryManager::CheckResultSet(std::shared_ptr<DataShareResultSet> &resultSet)
{
    if (resultSet == nullptr) {
        MEDIA_ERR_LOG("Input resultset is nullptr");
        return E_FAIL;
    }
    int count = 0;
    auto ret = resultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to get resultset row count, ret: %{public}d", ret);
        return ret;
    }
    if (count <= 0) {
        MEDIA_ERR_LOG("Failed to get count, count: %{public}d", count);
        return E_FAIL;
    }
    ret = resultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Failed to go to first row, ret: %{public}d", ret);
        return ret;
    }
    return E_SUCCESS;
}

static std::shared_ptr<DataShareResultSet> GetFilePathResultSetFromDb(const string &virId, sptr<IRemoteObject> token)
{
    GetFilePathFromUriReqBody reqBody;
    GetFilePathFromUriRespBody respBody;
    reqBody.virtualId = virId;

    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_FILEPATH_FROM_URI);
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "dataShareHelper is null");
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    if (errCode != 0) {
        MEDIA_ERR_LOG("after IPC::UserDefineIPCClient().Call, errCode: %{public}d.", errCode);
    }
    return respBody.resultSet;
}

int32_t MediaLibraryManager::GetFilePathFromUri(const Uri &fileUri, string &filePath, string userId)
{
    string uri = fileUri.ToString();
    MediaFileUri virtualUri(uri);
    CHECK_AND_RETURN_RET(virtualUri.IsValid(), E_URI_INVALID);
    string virtualId = virtualUri.GetFileId();
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (MediaFileUtils::GetTableFromVirtualUri(uri) != MEDIALIBRARY_TABLE) {
        MEDIA_INFO_LOG("uri:%{private}s does not match Files Table", uri.c_str());
        return E_URI_INVALID;
    }
#endif
    vector<string> columns = { MEDIA_DATA_DB_FILE_PATH };
    auto resultSet = GetFilePathResultSetFromDb(virtualId, token_);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INVALID_URI,
        "GetFilePathFromUri::uri is not correct: %{private}s", uri.c_str());
    if (CheckResultSet(resultSet) != E_SUCCESS) {
        return E_FAIL;
    }

    std::string tempPath = ResultSetUtils::GetStringValFromColumn(1, resultSet);
    if (tempPath.find(ROOT_MEDIA_DIR) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string relativePath = tempPath.substr((ROOT_MEDIA_DIR + DOCS_PATH).length());
    auto pos = relativePath.find('/');
    if (pos == string::npos) {
        return E_INVALID_ARGUMENTS;
    }
    relativePath = relativePath.substr(0, pos + 1);
    if ((relativePath != DOC_DIR_VALUES) && (relativePath != DOWNLOAD_DIR_VALUES)) {
        return E_DIR_CHECK_DIR_FAIL;
    }

    string prePath = PRE_PATH_VALUES;
    string postpath = tempPath.substr(prePath.length());
    tempPath = prePath + userId + "/" + postpath;
    filePath = tempPath;
    return E_SUCCESS;
}

static std::shared_ptr<DataShareResultSet> GetUriResultSetFromDb(
    const string &tempPath, sptr<IRemoteObject> token)
{
    GetUriFromFilePathReqBody reqBody;
    GetUriFromFilePathRespBody respBody;
    reqBody.tempPath = tempPath;

    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_URI_FROM_FILEPATH);
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, nullptr, "dataShareHelper is null");
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    if (errCode != 0) {
        MEDIA_ERR_LOG("after IPC::UserDefineIPCClient().Call, errCode: %{public}d.", errCode);
    }
    return respBody.resultSet;
}

int32_t MediaLibraryManager::GetUriFromFilePath(const string &filePath, Uri &fileUri, string &userId)
{
    if (filePath.empty()) {
        return E_INVALID_PATH;
    }

    string tempPath;
    SolvePath(filePath, tempPath, userId);
    if (tempPath.find(ROOT_MEDIA_DIR) != 0) {
        return E_CHECK_ROOT_DIR_FAIL;
    }
    string relativePath = tempPath.substr((ROOT_MEDIA_DIR + DOCS_PATH).length());
    auto pos = relativePath.find('/');
    if (pos == string::npos) {
        return E_INVALID_ARGUMENTS;
    }
    relativePath = relativePath.substr(0, pos + 1);
    if ((relativePath != DOC_DIR_VALUES) && (relativePath != DOWNLOAD_DIR_VALUES)) {
        return E_DIR_CHECK_DIR_FAIL;
    }

    vector<string> columns = { MEDIA_DATA_DB_ID};
    auto resultSet = GetUriResultSetFromDb(tempPath, token_);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_INVALID_URI,
        "GetUriFromFilePath::tempPath is not correct: %{private}s", tempPath.c_str());
    if (CheckResultSet(resultSet) != E_SUCCESS) {
        return E_FAIL;
    }

    int32_t fileId = ResultSetUtils::GetIntValFromColumn(0, resultSet);
#ifdef MEDIALIBRARY_COMPATIBILITY
    int64_t virtualId = MediaFileUtils::GetVirtualIdByType(fileId, MediaType::MEDIA_TYPE_FILE);
    fileUri = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(virtualId), "", MEDIA_API_VERSION_V9);
#else
    fileUri = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(fileId), "", MEDIA_API_VERSION_V9);
#endif
    return E_SUCCESS;
}

std::string MediaLibraryManager::GetSandboxPath(const std::string &path, const Size &size, bool isAstc)
{
    if (path.length() < ROOT_MEDIA_DIR.length()) {
        return "";
    }
    int min = std::min(size.width, size.height);
    int max = std::max(size.width, size.height);
    std::string suffixStr = path.substr(ROOT_MEDIA_DIR.length()) + "/";
    if (min == DEFAULT_ORIGINAL && max == DEFAULT_ORIGINAL) {
        suffixStr += "LCD.jpg";
    } else if (min <= DEFAULT_THUMBNAIL_SIZE && max <= MAX_DEFAULT_THUMBNAIL_SIZE) {
        suffixStr += isAstc ? "THM_ASTC.astc" : "THM.jpg";
    } else {
        suffixStr += "LCD.jpg";
    }

    return ROOT_SANDBOX_DIR + ".thumbs/" + suffixStr;
}

static int32_t GetFdFromSandbox(const string &path, string &sandboxPath, bool isAstc)
{
    int32_t fd = -1;
    CHECK_AND_RETURN_RET_LOG(!sandboxPath.empty(), fd, "OpenThumbnail sandboxPath is empty, path :%{public}s",
        MediaFileUtils::DesensitizePath(path).c_str());
    string absFilePath;
    CHECK_AND_RETURN_RET(!PathToRealPath(sandboxPath, absFilePath), open(absFilePath.c_str(), O_RDONLY));
    CHECK_AND_RETURN_RET(isAstc, fd);
    string suffixStr = "THM_ASTC.astc";
    size_t thmIdx = sandboxPath.find(suffixStr);
    CHECK_AND_RETURN_RET(thmIdx != std::string::npos, fd);
    sandboxPath.replace(thmIdx, suffixStr.length(), "THM.jpg");
    CHECK_AND_RETURN_RET(PathToRealPath(sandboxPath, absFilePath), fd);
    return open(absFilePath.c_str(), O_RDONLY);
}

static void UpdateAssetVisitCount(shared_ptr<DataShare::DataShareHelper> dataShareHelper, const string &fileIdStr)
{
    MEDIA_INFO_LOG("UpdateAssetVisitCount fileIdStr :%{public}s", fileIdStr.c_str());
    AddAssetVisitCountReqBody reqBody;
    reqBody.fileId = fileIdStr.empty() ? -1 : atoi(fileIdStr.c_str());
    reqBody.visitType = 1; // LCD

    int32_t businessCode = static_cast<int32_t>(MediaLibraryBusinessCode::INNER_ADD_ASSET_VISIT_COUNT);
    int32_t errCode = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody);
    if (errCode < 0) {
        MEDIA_ERR_LOG("after IPC::UserDefineIPCClient().Call, errCode: %{public}d.", errCode);
    }
}

int MediaLibraryManager::OpenThumbnail(string &uriStr, const string &path, const Size &size, bool isAstc)
{
    // To ensure performance.
    std::string str = uriStr;
    size_t pos = str.find(MULTI_USER_URI_FLAG);
    std::string userId = "";
    if (pos != std::string::npos) {
        pos += MULTI_USER_URI_FLAG.length();
        size_t end = str.find_first_of("&?", pos);
        CHECK_AND_EXECUTE(end != std::string::npos, end = str.length());
        userId = str.substr(pos, end - pos);
        MEDIA_ERR_LOG("OpenThumbnail for other user is %{public}s", userId.c_str());
    }
    shared_ptr<DataShare::DataShareHelper> dataShareHelper = userId != "" ? DataShare::DataShareHelper::Creator(token_,
        MEDIALIBRARY_DATA_URI + "?" + MULTI_USER_URI_FLAG + userId) : sDataShareHelper_;
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_ERR, "Failed to open thumbnail, dataShareHelper is nullptr");
    if (path.empty()) {
        MEDIA_ERR_LOG("OpenThumbnail path is empty");
        Uri openUri(uriStr);
        return dataShareHelper->OpenFile(openUri, "R");
    }
    string sandboxPath = GetSandboxPath(path, size, isAstc);
    int32_t fd = GetFdFromSandbox(path, sandboxPath, isAstc);
    if (fd > 0 && sandboxPath.find("LCD.jpg") != std::string::npos) {
        UpdateAssetVisitCount(dataShareHelper, MediaFileUtils::GetIdFromUri(uriStr));
    }
    CHECK_AND_RETURN_RET(fd <= 0, fd);
    MEDIA_INFO_LOG("OpenThumbnail from andboxPath failed, errno %{public}d path :%{public}s fd %{public}d",
        errno, MediaFileUtils::DesensitizePath(path).c_str(), fd);
    CHECK_AND_EXECUTE(!IsAsciiString(path), uriStr += "&" + THUMBNAIL_PATH + "=" + path);
    Uri openUri(uriStr);
    return dataShareHelper->OpenFile(openUri, "R");
}

/**
 * Get the file uri prefix with id
 * eg. Input: file://media/Photo/10/IMG_xxx/01.jpg
 *     Output: file://media/Photo/10
 */
void MediaLibraryManager::GetUriIdPrefix(std::string &fileUri)
{
    MediaFileUri mediaUri(fileUri);
    CHECK_AND_RETURN(mediaUri.IsApi10());
    auto slashIdx = fileUri.rfind('/');
    if (slashIdx == std::string::npos) {
        return;
    }
    auto tmpUri = fileUri.substr(0, slashIdx);
    slashIdx = tmpUri.rfind('/');
    if (slashIdx == std::string::npos) {
        return;
    }
    fileUri = tmpUri.substr(0, slashIdx);
}

static void GetUriParamsFromQueryKey(UriParams& uriParams,
    std::unordered_map<std::string, std::string>& queryKey)
{
    if (queryKey.count(THUMBNAIL_PATH) != 0) {
        uriParams.path = queryKey[THUMBNAIL_PATH];
    }
    if (queryKey.count(THUMBNAIL_WIDTH) != 0) {
        if (MediaFileUtils::IsValidInteger(queryKey[THUMBNAIL_WIDTH])) {
            uriParams.size.width = stoi(queryKey[THUMBNAIL_WIDTH]);
        }
    }
    if (queryKey.count(THUMBNAIL_HEIGHT) != 0) {
        if (MediaFileUtils::IsValidInteger(queryKey[THUMBNAIL_HEIGHT])) {
            uriParams.size.height = stoi(queryKey[THUMBNAIL_HEIGHT]);
        }
    }
    if (queryKey.count(THUMBNAIL_OPER) != 0) {
        uriParams.isAstc = queryKey[THUMBNAIL_OPER] == MEDIA_DATA_DB_THUMB_ASTC;
    }
    if (queryKey.count(THUMBNAIL_USER) != 0) {
        uriParams.user = queryKey[THUMBNAIL_USER];
    }
    uriParams.dynamicRange = DecodeDynamicRange::AUTO;
    if (queryKey.count(DYNAMIC_RANGE) != 0) {
        if (MediaFileUtils::IsValidInteger(queryKey[DYNAMIC_RANGE])) {
            uriParams.dynamicRange = static_cast<DecodeDynamicRange>(stoi(queryKey[DYNAMIC_RANGE]));
        }
    }
}

static bool GetParamsFromUri(const string &uri, const bool isOldVer, UriParams &uriParams)
{
    MediaFileUri mediaUri(uri);
    CHECK_AND_RETURN_RET(mediaUri.IsValid(), false);
    if (isOldVer) {
        auto index = uri.find("thumbnail");
        if (index == string::npos || index == 0) {
            return false;
        }
        uriParams.fileUri = uri.substr(0, index - 1);
        MediaLibraryManager::GetUriIdPrefix(uriParams.fileUri);
        index += strlen("thumbnail");
        index = uri.find('/', index);
        CHECK_AND_RETURN_RET(index != string::npos, false);

        index += 1;
        auto tmpIdx = uri.find('/', index);
        CHECK_AND_RETURN_RET(tmpIdx != string::npos, false);

        int32_t width = 0;
        StrToInt(uri.substr(index, tmpIdx - index), width);
        int32_t height = 0;
        StrToInt(uri.substr(tmpIdx + 1), height);
        uriParams.size = { .width = width, .height = height };
    } else {
        auto qIdx = uri.find('?');
        if (qIdx == string::npos) {
            return false;
        }
        uriParams.fileUri = uri.substr(0, qIdx);
        MediaLibraryManager::GetUriIdPrefix(uriParams.fileUri);
        auto &queryKey = mediaUri.GetQueryKeys();
        GetUriParamsFromQueryKey(uriParams, queryKey);
    }
    return true;
}

bool MediaLibraryManager::IfSizeEqualsRatio(const Size &imageSize, const Size &targetSize)
{
    bool cond = (imageSize.height <= 0 || targetSize.height <= 0);
    CHECK_AND_RETURN_RET(!cond, false);
    float imageSizeScale = static_cast<float>(imageSize.width) / static_cast<float>(imageSize.height);
    float targetSizeScale = static_cast<float>(targetSize.width) / static_cast<float>(targetSize.height);
    if (imageSizeScale - targetSizeScale > FLOAT_EPSILON || targetSizeScale - imageSizeScale > FLOAT_EPSILON) {
        return false;
    } else {
        return true;
    }
}

unique_ptr<PixelMap> MediaLibraryManager::DecodeThumbnail(UniqueFd& uniqueFd, const Size& size,
    DecodeDynamicRange dynamicRange)
{
    MediaLibraryTracer tracer;
    tracer.Start("ImageSource::CreateImageSource");
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "CreateImageSource err %{public}d", err);

    ImageInfo imageInfo;
    err = imageSource->GetImageInfo(0, imageInfo);
    CHECK_AND_RETURN_RET_LOG(err == E_OK, nullptr, "GetImageInfo err %{public}d", err);

    bool isEqualsRatio = IfSizeEqualsRatio(imageInfo.size, size);
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = isEqualsRatio ? size : imageInfo.size;
    decodeOpts.desiredDynamicRange = dynamicRange;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "CreatePixelMap err %{public}d", err);

    PostProc postProc;
    bool cond = (size.width != 0 && size.width != DEFAULT_ORIGINAL && !isEqualsRatio &&
        !postProc.CenterScale(size, *pixelMap));
    CHECK_AND_RETURN_RET_LOG(!cond, nullptr, "CenterScale failed, size: %{public}d * %{public}d,"
        " imageInfo size: %{public}d * %{public}d", size.width, size.height,
        imageInfo.size.width, imageInfo.size.height);

    // Make the ashmem of pixelmap to be purgeable after the operation on ashmem.
    // And then make the pixelmap subject to PurgeableManager's control.
#ifdef IMAGE_PURGEABLE_PIXELMAP
    PurgeableBuilder::MakePixelMapToBePurgeable(pixelMap, imageSource, decodeOpts, size);
#endif
    return pixelMap;
}

unique_ptr<PixelMap> MediaLibraryManager::QueryThumbnail(UriParams& params)
{
    MediaLibraryTracer tracer;
    tracer.Start("QueryThumbnail uri:" + params.fileUri);

    string oper = params.isAstc ? MEDIA_DATA_DB_THUMB_ASTC : MEDIA_DATA_DB_THUMBNAIL;
    string openUriStr = params.fileUri + "?" + MEDIA_OPERN_KEYWORD + "=" + oper + "&" + MEDIA_DATA_DB_WIDTH +
        "=" + to_string(params.size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(params.size.height);
    if (params.user != "") {
        openUriStr = openUriStr + "&" + THUMBNAIL_USER + "=" + params.user;
        bool cond = (!params.path.empty() && !params.path.find(MULTI_USER_URI_FLAG));
        CHECK_AND_EXECUTE(!cond, params.path = params.path + "&" + THUMBNAIL_USER + "=" + params.user);
    }
    tracer.Start("DataShare::OpenThumbnail");
    UniqueFd uniqueFd(MediaLibraryManager::OpenThumbnail(openUriStr, params.path, params.size, params.isAstc));
    CHECK_AND_RETURN_RET_LOG(uniqueFd.Get() >= 0, nullptr, "queryThumb is null, errCode is %{public}d", uniqueFd.Get());
    tracer.Finish();
    return DecodeThumbnail(uniqueFd, params.size, params.dynamicRange);
}

std::unique_ptr<PixelMap> MediaLibraryManager::GetThumbnail(const Uri &uri)
{
    // uri is dataability:///media/image/<id>/thumbnail/<width>/<height>
    string uriStr = uri.ToString();
    auto thumbLatIdx = uriStr.find("thumbnail");
    bool isAstc = false;
    if (thumbLatIdx == string::npos || thumbLatIdx > uriStr.length()) {
        thumbLatIdx = uriStr.find("astc");
        if (thumbLatIdx == string::npos || thumbLatIdx > uriStr.length()) {
            MEDIA_ERR_LOG("GetThumbnail failed, oper is invalid");
            return nullptr;
        }
        isAstc = true;
    }
    thumbLatIdx += isAstc ? strlen("astc") : strlen("thumbnail");
    bool isOldVersion = uriStr[thumbLatIdx] == '/';
    UriParams uriParams;
    if (!GetParamsFromUri(uriStr, isOldVersion, uriParams)) {
        MEDIA_ERR_LOG("GetThumbnail failed, get params from uri failed, uri :%{public}s", uriStr.c_str());
        return nullptr;
    }
    auto pixelmap = QueryThumbnail(uriParams);
    if (pixelmap == nullptr) {
        MEDIA_ERR_LOG("pixelmap is null, uri :%{public}s, path :%{public}s",
            uriParams.fileUri.c_str(), MediaFileUtils::DesensitizePath(uriParams.path).c_str());
    }
    return pixelmap;
}

static int32_t GetAstcsByOffset(const vector<string> &uriBatch, vector<vector<uint8_t>> &astcBatch)
{
    UriParams uriParams;
    if (!GetParamsFromUri(uriBatch.at(0), false, uriParams)) {
        MEDIA_ERR_LOG("GetParamsFromUri failed in GetAstcsByOffset");
        return E_INVALID_URI;
    }
    vector<string> timeIdBatch;
    int32_t start = 0;
    int32_t count = 0;
    MediaFileUri::GetTimeIdFromUri(uriBatch, timeIdBatch, start, count);
    CHECK_AND_RETURN_RET_LOG(!timeIdBatch.empty(), E_INVALID_URI, "GetTimeIdFromUri failed");
    MEDIA_INFO_LOG("GetAstcsByOffset image batch size: %{public}zu, begin: %{public}s, end: %{public}s,"
        "start: %{public}d, count: %{public}d", uriBatch.size(), timeIdBatch.back().c_str(),
        timeIdBatch.front().c_str(), start, count);

    KvStoreValueType valueType;
    if (uriParams.size.width == DEFAULT_MONTH_THUMBNAIL_SIZE && uriParams.size.height == DEFAULT_MONTH_THUMBNAIL_SIZE) {
        valueType = KvStoreValueType::MONTH_ASTC;
    } else if (uriParams.size.width == DEFAULT_YEAR_THUMBNAIL_SIZE &&
        uriParams.size.height == DEFAULT_YEAR_THUMBNAIL_SIZE) {
        valueType = KvStoreValueType::YEAR_ASTC;
    } else {
        MEDIA_ERR_LOG("GetAstcsByOffset invalid image size");
        return E_INVALID_URI;
    }

    vector<string> newTimeIdBatch;
    MediaAssetRdbStore::GetInstance()->QueryTimeIdBatch(start, count, newTimeIdBatch);
    auto kvStore = MediaLibraryKvStoreManager::GetInstance().GetKvStore(KvStoreRoleType::VISITOR, valueType);
    if (kvStore == nullptr) {
        MEDIA_ERR_LOG("GetAstcsByOffset kvStore is nullptr");
        return E_DB_FAIL;
    }
    int32_t status = kvStore->BatchQuery(newTimeIdBatch, astcBatch);
    if (status != E_OK) {
        MEDIA_ERR_LOG("GetAstcsByOffset failed, status %{public}d", status);
        return status;
    }
    return E_OK;
}

static int32_t GetAstcsBatch(const vector<string> &uriBatch, vector<vector<uint8_t>> &astcBatch)
{
    UriParams uriParams;
    if (!GetParamsFromUri(uriBatch.at(0), false, uriParams)) {
        MEDIA_ERR_LOG("GetParamsFromUri failed in GetAstcsBatch");
        return E_INVALID_URI;
    }
    vector<string> timeIdBatch;
    MediaFileUri::GetTimeIdFromUri(uriBatch, timeIdBatch);
    CHECK_AND_RETURN_RET_LOG(!timeIdBatch.empty(), E_INVALID_URI, "GetTimeIdFromUri failed");
    MEDIA_INFO_LOG("GetAstcsBatch image batch size: %{public}zu, begin: %{public}s, end: %{public}s",
        uriBatch.size(), timeIdBatch.back().c_str(), timeIdBatch.front().c_str());

    KvStoreValueType valueType;
    if (uriParams.size.width == DEFAULT_MONTH_THUMBNAIL_SIZE && uriParams.size.height == DEFAULT_MONTH_THUMBNAIL_SIZE) {
        valueType = KvStoreValueType::MONTH_ASTC;
    } else if (uriParams.size.width == DEFAULT_YEAR_THUMBNAIL_SIZE &&
        uriParams.size.height == DEFAULT_YEAR_THUMBNAIL_SIZE) {
        valueType = KvStoreValueType::YEAR_ASTC;
    } else {
        MEDIA_ERR_LOG("GetAstcsBatch invalid image size");
        return E_INVALID_URI;
    }

    auto kvStore = MediaLibraryKvStoreManager::GetInstance().GetKvStore(KvStoreRoleType::VISITOR, valueType);
    CHECK_AND_RETURN_RET_LOG(kvStore != nullptr, E_DB_FAIL, "GetAstcsBatch kvStore is nullptr");
    int32_t status = kvStore->BatchQuery(timeIdBatch, astcBatch);
    CHECK_AND_RETURN_RET_LOG(status == E_OK, status, "GetAstcsBatch failed, status %{public}d", status);
    return E_OK;
}

int32_t MediaLibraryManager::GetBatchAstcs(const vector<string> &uriBatch, vector<vector<uint8_t>> &astcBatch)
{
    if (uriBatch.empty()) {
        MEDIA_INFO_LOG("GetBatchAstcs uriBatch is empty");
        return E_INVALID_URI;
    }
    if (uriBatch.at(0).find(ML_URI_OFFSET) != std::string::npos) {
        return GetAstcsByOffset(uriBatch, astcBatch);
    } else {
        return GetAstcsBatch(uriBatch, astcBatch);
    }
}

unique_ptr<PixelMap> MediaLibraryManager::DecodeAstc(UniqueFd &uniqueFd)
{
    if (uniqueFd.Get() < 0) {
        MEDIA_ERR_LOG("Fd is invalid, errCode is %{public}d", uniqueFd.Get());
        return nullptr;
    }
    MediaLibraryTracer tracer;
    tracer.Start("MediaLibraryManager::DecodeAstc");
    SourceOptions opts;
    uint32_t err = 0;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "CreateImageSource err %{public}d", err);

    DecodeOptions decodeOpts;
    decodeOpts.fastAstc = true;
    decodeOpts.allocatorType = AllocatorType::SHARE_MEM_ALLOC;
    unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "CreatePixelMap err %{public}d", err);
    return pixelMap;
}

std::unique_ptr<PixelMap> MediaLibraryManager::GetAstc(const Uri &uri)
{
    // uri is file://media/image/<id>&oper=astc&width=<width>&height=<height>&path=<path>
    MediaLibraryTracer tracer;
    string uriStr = uri.ToString();
    if (uriStr.empty()) {
        MEDIA_ERR_LOG("GetAstc failed, uri is empty");
        return nullptr;
    }
    auto astcIndex = uriStr.find("astc");
    if (astcIndex == string::npos || astcIndex > uriStr.length()) {
        MEDIA_ERR_LOG("GetAstc failed, oper is invalid");
        return nullptr;
    }
    UriParams uriParams;
    if (!GetParamsFromUri(uriStr, false, uriParams)) {
        MEDIA_ERR_LOG("GetAstc failed, get params from uri failed, uri :%{public}s", uriStr.c_str());
        return nullptr;
    }
    tracer.Start("GetAstc uri:" + uriParams.fileUri);
    string openUriStr = uriParams.fileUri + "?" + MEDIA_OPERN_KEYWORD + "=" +
        MEDIA_DATA_DB_THUMB_ASTC + "&" + MEDIA_DATA_DB_WIDTH + "=" + to_string(uriParams.size.width) +
            "&" + MEDIA_DATA_DB_HEIGHT + "=" + to_string(uriParams.size.height);
    if (uriParams.user != "") {
        openUriStr = openUriStr + "&" + THUMBNAIL_USER + "=" + uriParams.user;
        if (!uriParams.path.empty() && !uriParams.path.find(MULTI_USER_URI_FLAG)) {
            uriParams.path = uriParams.path + "&" + THUMBNAIL_USER + "=" + uriParams.user;
        }
    }
    tracer.Start("MediaLibraryManager::OpenThumbnail");
    UniqueFd uniqueFd(MediaLibraryManager::OpenThumbnail(openUriStr, uriParams.path, uriParams.size, true));
    if (uniqueFd.Get() < 0) {
        MEDIA_ERR_LOG("OpenThumbnail failed, errCode is %{public}d, uri :%{public}s, path :%{public}s",
            uniqueFd.Get(), uriParams.fileUri.c_str(), MediaFileUtils::DesensitizePath(uriParams.path).c_str());
        return nullptr;
    }
    tracer.Finish();
    auto pixelmap = DecodeAstc(uniqueFd);
    if (pixelmap == nullptr) {
        MEDIA_ERR_LOG("pixelmap is null, uri :%{public}s, path :%{public}s",
            uriParams.fileUri.c_str(), MediaFileUtils::DesensitizePath(uriParams.path).c_str());
    }
    return pixelmap;
}

int32_t MediaLibraryManager::OpenReadOnlyAppSandboxVideo(const string& uri)
{
    std::vector<std::string> uris;
    if (!MediaFileUtils::SplitMovingPhotoUri(uri, uris)) {
        return -1;
    }
    AppFileService::ModuleFileUri::FileUri fileUri(uris[MOVING_PHOTO_VIDEO_POS]);
    std::string realPath = fileUri.GetRealPath();
    int32_t fd = open(realPath.c_str(), O_RDONLY);
    if (fd < 0) {
        MEDIA_ERR_LOG("Failed to open read only video file, errno: %{public}d", errno);
        return -1;
    }
    return fd;
}

int32_t MediaLibraryManager::ReadMovingPhotoVideo(const string &uri, const string &option)
{
    std::string str = uri;
    size_t pos = str.find(MULTI_USER_URI_FLAG);
    std::string userId = "";
    if (pos != std::string::npos) {
        pos += MULTI_USER_URI_FLAG.length();
        size_t end = str.find_first_of("&?", pos);
        if (end == std::string::npos) {
            end = str.length();
        }
        userId = str.substr(pos, end - pos);
        MEDIA_INFO_LOG("ReadMovingPhotoVideo for other user is %{public}s", userId.c_str());
    }
    shared_ptr<DataShare::DataShareHelper> dataShareHelper = userId != "" ?
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI + "?" + MULTI_USER_URI_FLAG + userId) :
        sDataShareHelper_;
    if (!MediaFileUtils::IsMediaLibraryUri(uri)) {
        return OpenReadOnlyAppSandboxVideo(uri);
    }
    if (!CheckPhotoUri(uri)) {
        MEDIA_ERR_LOG("invalid uri: %{public}s", uri.c_str());
        return E_ERR;
    }

    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_ERR,
        "Failed to read video of moving photo, datashareHelper is nullptr");
    string videoUri = uri;
    MediaFileUtils::UriAppendKeyValue(videoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, option);
    Uri openVideoUri(videoUri);
    return dataShareHelper->OpenFile(openVideoUri, MEDIA_FILEMODE_READONLY);
}

int32_t MediaLibraryManager::ReadMovingPhotoVideo(const string &uri)
{
    return ReadMovingPhotoVideo(uri, OPEN_MOVING_PHOTO_VIDEO);
}

int32_t MediaLibraryManager::ReadMovingPhotoVideo(const string &uri, off_t &offset)
{
    int32_t fd = ReadMovingPhotoVideo(uri, OPEN_MOVING_PHOTO_VIDEO_CLOUD);
    if (fd < 0) {
        MEDIA_ERR_LOG("Failed to open video of moving photo: %{public}d", fd);
        return E_ERR;
    }

    if (!MediaFileUtils::IsMediaLibraryUri(uri)) {
        return fd;
    }

    int64_t liveSize = 0;
    if (MovingPhotoFileUtils::GetLivePhotoSize(fd, liveSize) != E_OK) {
        return fd;
    }

    struct stat st;
    if (fstat(fd, &st) != E_OK || st.st_size < liveSize + PLAY_INFO_LEN + LIVE_TAG_LEN) {
        MEDIA_ERR_LOG("video size is wrong");
        return E_ERR;
    }
    offset = st.st_size - liveSize - PLAY_INFO_LEN - LIVE_TAG_LEN;
    MEDIA_DEBUG_LOG("offset is %{public}" PRId64, offset);
    return fd;
}

int32_t MediaLibraryManager::ReadPrivateMovingPhoto(const string &uri)
{
    if (!CheckPhotoUri(uri)) {
        MEDIA_ERR_LOG("invalid uri: %{public}s", uri.c_str());
        return E_ERR;
    }
    CHECK_AND_RETURN_RET_LOG(sDataShareHelper_ != nullptr, E_ERR,
        "Failed to read video of moving photo, datashareHelper is nullptr");
    string movingPhotoUri = uri;
    MediaFileUtils::UriAppendKeyValue(movingPhotoUri, MEDIA_MOVING_PHOTO_OPRN_KEYWORD, OPEN_PRIVATE_LIVE_PHOTO);
    Uri openMovingPhotoUri(movingPhotoUri);
    return sDataShareHelper_->OpenFile(openMovingPhotoUri, MEDIA_FILEMODE_READONLY);
}

std::string MediaLibraryManager::GetMovingPhotoImageUri(const string &uri)
{
    if (uri.empty()) {
        MEDIA_ERR_LOG("invalid uri: %{public}s", uri.c_str());
        return "";
    }
    if (MediaFileUtils::IsMediaLibraryUri(uri)) {
        return uri;
    }
    std::vector<std::string> uris;
    CHECK_AND_RETURN_RET(MediaFileUtils::SplitMovingPhotoUri(uri, uris), "");
    return uris[MOVING_PHOTO_IMAGE_POS];
}

int64_t MediaLibraryManager::GetSandboxMovingPhotoTime(const string& uri)
{
    vector<string> uris;
    CHECK_AND_RETURN_RET(MediaFileUtils::SplitMovingPhotoUri(uri, uris), E_ERR);
    AppFileService::ModuleFileUri::FileUri imageFileUri(uris[MOVING_PHOTO_IMAGE_POS]);
    string imageRealPath = imageFileUri.GetRealPath();
    struct stat imageStatInfo {};
    CHECK_AND_RETURN_RET_LOG(stat(imageRealPath.c_str(), &imageStatInfo) == 0, E_ERR, "stat image error");

    int64_t imageDateModified = static_cast<int64_t>(MediaFileUtils::Timespec2Millisecond(imageStatInfo.st_mtim));
    AppFileService::ModuleFileUri::FileUri videoFileUri(uris[MOVING_PHOTO_VIDEO_POS]);
    string videoRealPath = videoFileUri.GetRealPath();
    struct stat videoStatInfo {};
    CHECK_AND_RETURN_RET_LOG(stat(videoRealPath.c_str(), &videoStatInfo) == 0, E_ERR, "stat video error");
    int64_t videoDateModified = static_cast<int64_t>(MediaFileUtils::Timespec2Millisecond(videoStatInfo.st_mtim));
    return imageDateModified >= videoDateModified ? imageDateModified : videoDateModified;
}

static int64_t GetMovingPhotoDateModifiedIPCExecute(
    const std::shared_ptr<DataShare::DataShareHelper> &helper, const string &fileId)
{
    GetMovingPhotoDateModifiedReqBody reqBody;
    GetMovingPhotoDateModifiedRespBody respBody;
    reqBody.fileId = fileId;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_GET_MOVING_PHOTO_DATE_MODIFIED);

    int32_t err = IPC::UserInnerIPCClient().SetDataShareHelper(helper).Call(businessCode, reqBody, respBody);
    if (err != E_OK) {
        MEDIA_ERR_LOG("get position fail. err:%{public}d", err);
        return E_ERR;
    }

    return respBody.dateModified;
}

int64_t MediaLibraryManager::GetMovingPhotoDateModified(const string &uri)
{
    CHECK_AND_RETURN_RET_LOG(!uri.empty(), E_ERR, "Failed to check empty uri");
    if (!MediaFileUtils::IsMediaLibraryUri(uri)) {
        return GetSandboxMovingPhotoTime(uri);
    }

    CHECK_AND_RETURN_RET_LOG(CheckPhotoUri(uri), E_ERR, "Failed to check invalid uri: %{public}s", uri.c_str());
    Uri queryUri(PAH_QUERY_PHOTO);
    DataSharePredicates predicates;
    string fileId = MediaFileUtils::GetIdFromUri(uri);
    predicates.EqualTo(MediaColumn::MEDIA_ID, fileId);

    CHECK_AND_RETURN_RET_LOG(sDataShareHelper_ != nullptr, E_ERR, "sDataShareHelper_ is null");
    OperationObject object = OperationObject::UNKNOWN_OBJECT;
    if (!MediaAssetRdbStore::GetInstance()->IsQueryAccessibleViaSandBox(queryUri, object, predicates)) {
        return GetMovingPhotoDateModifiedIPCExecute(sDataShareHelper_, fileId);
    }

    DatashareBusinessError businessError;
    vector<string> columns = {
        MediaColumn::MEDIA_DATE_MODIFIED,
    };
    auto queryResultSet = sDataShareHelper_->Query(queryUri, predicates, columns, &businessError);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, E_ERR, "queryResultSet is null");
    CHECK_AND_RETURN_RET_LOG(queryResultSet->GoToNextRow() == NativeRdb::E_OK, E_ERR, "Failed to GoToNextRow");
    return GetInt64Val(MediaColumn::MEDIA_DATE_MODIFIED, queryResultSet);
}

shared_ptr<PhotoAssetProxy> MediaLibraryManager::CreatePhotoAssetProxy(CameraShotType cameraShotType,
    uint32_t callingUid, int32_t userId, uint32_t callingTokenId)
{
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    MEDIA_INFO_LOG("dataShareHelper is ready, ret = %{public}d.", dataShareHelper != nullptr);
    shared_ptr<PhotoAssetProxy> photoAssetProxy = make_shared<PhotoAssetProxy>(dataShareHelper, cameraShotType,
        callingUid, userId, callingTokenId);
    return photoAssetProxy;
}

std::unordered_map<std::string, std::string> MediaLibraryManager::GetUrisByOldUris(std::vector<std::string> uris)
{
    MEDIA_INFO_LOG("Start request uris by old uris, size: %{public}zu", uris.size());
    return TabOldPhotosClient(*this).GetUrisByOldUris(uris);
}

int32_t MediaLibraryManager::GetAlbumLpath(uint32_t ownerAlbumId, std::string &lpath)
{
    MEDIA_DEBUG_LOG("MediaLibraryManager::GetAlbumLpath Start.");
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_FAIL, "dataShareHelper is nullptr");

    GetAlbumsLpathByIdsReqBody reqBody;
    reqBody.albumId = ownerAlbumId;
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_PAH_QUERY_GET_ALBUMS_BY_IDS);
    GetAlbumsLpathByIdsRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "after IPC::UserDefineIPCClient().Call, errCode: %{public}d.",
        errCode);
    lpath = respBody.lpath;
    MEDIA_DEBUG_LOG("MediaLibraryManager::GetAlbumLpath End. lpath: %{public}s", lpath.c_str());
    return errCode;
}

int32_t MediaLibraryManager::GetAlbumLpaths(uint32_t albumType, std::shared_ptr<DataShare::ResultSet> &resultSet)
{
    MEDIA_DEBUG_LOG("MediaLibraryManager::GetAlbumLpaths Start.");
    CHECK_AND_RETURN_RET_LOG(albumType == PhotoAlbumType::USER || albumType == PhotoAlbumType::SOURCE, E_FAIL,
        "GetAlbumLpaths albumType not support");
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_FAIL, "dataShareHelper is nullptr");

    QueryAlbumsReqBody reqBody;
    reqBody.albumType = static_cast<int32_t>(albumType);
    reqBody.albumSubType =
        (albumType == PhotoAlbumType::SOURCE ? PhotoAlbumSubType::SOURCE_GENERIC : PhotoAlbumSubType::USER_GENERIC);
    reqBody.columns = { PhotoAlbumColumns::ALBUM_ID, PhotoAlbumColumns::ALBUM_LPATH};
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_PAH_QUERY_PHOTO_ALBUMS);
    QueryAlbumsRespBody respBody;
    int32_t errCode =
        IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody, respBody);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "after IPC::UserDefineIPCClient().Call, errCode: %{public}d.",
        errCode);
    resultSet = respBody.resultSet;
    MEDIA_DEBUG_LOG("MediaLibraryManager::GetAlbumLpaths End.");
    return errCode;
}

int32_t MediaLibraryManager::RetainCloudMediaAsset(CloudMediaRetainType retainType)
{
    MEDIA_DEBUG_LOG("MediaLibraryManager::RetainCloudMediaAsset Start.");
    shared_ptr<DataShare::DataShareHelper> dataShareHelper =
        DataShare::DataShareHelper::Creator(token_, MEDIALIBRARY_DATA_URI);
    CHECK_AND_RETURN_RET_LOG(dataShareHelper != nullptr, E_FAIL, "dataShareHelper is nullptr");

    RetainCloudMediaAssetReqBody reqBody;
    reqBody.cloudMediaRetainType = static_cast<int32_t>(retainType);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::INNER_RETAIN_CLOUDMEDIA_ASSET);
    int32_t errCode = IPC::UserInnerIPCClient().SetDataShareHelper(dataShareHelper).Call(businessCode, reqBody);
    CHECK_AND_RETURN_RET_LOG(errCode == E_OK, errCode, "after IPC::UserDefineIPCClient().Call, errCode: %{public}d.",
        errCode);
    MEDIA_DEBUG_LOG("MediaLibraryManager::RetainCloudMediaAsset End.");
    return errCode;
}
} // namespace Media
} // namespace OHOS
