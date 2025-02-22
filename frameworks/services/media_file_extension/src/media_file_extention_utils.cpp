/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FileExtension"

#include "media_file_extention_utils.h"

#include <fcntl.h>

#include "file_access_extension_info.h"
#include "media_device_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "media_smart_map_column.h"
#include "medialibrary_client_errno.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_type_const.h"
#include "media_file_utils.h"
#include "mimetype_utils.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "thumbnail_utils.h"
#include "n_error.h"
#include "unique_fd.h"
#include "userfile_manager_types.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::FileAccessFwk;
using namespace OHOS::FileManagement::LibN;

namespace OHOS {
namespace Media {
namespace {
    constexpr int64_t MAX_COUNT = 2000;
    constexpr int COPY_EXCEPTION = -1;
    constexpr int COPY_NOEXCEPTION = -2;
}
constexpr int32_t ALBUM_MODE_READONLY = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ;
constexpr int32_t ALBUM_MODE_RW =
    DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
constexpr int32_t FILE_MODE_RW =
    DOCUMENT_FLAG_REPRESENTS_FILE | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;

static const std::vector<std::string> FILEINFO_COLUMNS = {
    MEDIA_DATA_DB_ID, MEDIA_DATA_DB_SIZE, MEDIA_DATA_DB_DATE_MODIFIED, MEDIA_DATA_DB_MIME_TYPE, MEDIA_DATA_DB_NAME,
    MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_IS_TRASH, MEDIA_DATA_DB_RELATIVE_PATH
};

static const std::unordered_map<int32_t, std::pair<int32_t, string>> mediaErrCodeMap {
    { E_PERMISSION_DENIED, { FILEIO_SYS_CAP_TAG + E_PERM,        "Operation not permitted"                    } },
    { E_NO_SUCH_FILE,      { FILEIO_SYS_CAP_TAG + E_NOENT,       "No such file or directory in media library" } },
    { E_FILE_EXIST,        { FILEIO_SYS_CAP_TAG + E_EXIST,       "The file is exist in media library"         } },
    { E_NO_MEMORY,         { FILEIO_SYS_CAP_TAG + E_NOMEM,       "Out of memory"                              } },
    { E_URI_INVALID,       { OHOS::FileManagement::LibN::E_URIS, "Invalid URI"                                } },
    { E_INVALID_URI,       { OHOS::FileManagement::LibN::E_URIS, "Invalid URI"                                } },
};

#ifdef MEDIALIBRARY_COMPATIBILITY
bool CheckDestRelativePath(const string destRelativePath)
{
    if (destRelativePath == "") {
        return true;
    }
    size_t size = destRelativePath.find_first_of("/");
    if (size == string::npos) {
        return false;
    }
    string path = destRelativePath.substr(0, size + 1);
    if (path != DOCS_PATH) {
        return false;
    }
    return true;
}
#endif

int MediaFileExtentionUtils::OpenFile(const Uri &uri, const int flags, int &fd)
{
    fd = -1;
    if (!CheckUriValid(uri.ToString())) {
        return E_URI_INVALID;
    }
    string networkId = MediaFileUtils::GetNetworkIdFromUri(uri.ToString());
    if (!networkId.empty() && flags != O_RDONLY) {
        return E_OPENFILE_INVALID_FLAG;
    }
    string mode;
    if (flags == O_RDONLY) {
        mode = MEDIA_FILEMODE_READONLY;
    } else if (flags == O_WRONLY) {
        mode = MEDIA_FILEMODE_WRITEONLY;
    } else if (flags == O_RDWR) {
        mode = MEDIA_FILEMODE_READWRITE;
    } else {
        MEDIA_ERR_LOG("invalid OpenFile flags %{public}d", flags);
        return E_OPENFILE_INVALID_FLAG;
    }
#ifdef MEDIALIBRARY_COMPATIBILITY
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(uri.ToString());
    MediaLibraryCommand cmd(Uri(realUri), OperationType::OPEN);
#else
    MediaLibraryCommand cmd(uri, OperationType::OPEN);
#endif
    auto ret = MediaLibraryDataManager::GetInstance()->OpenFile(cmd, mode);
    if (ret > 0) {
        fd = ret;
    }
    return ret;
}

#ifdef MEDIALIBRARY_COMPATIBILITY
static inline string GetUriFromId(int32_t id, const string &networkId)
{
    int64_t fileId = MediaFileUtils::GetVirtualIdByType(id, MediaType::MEDIA_TYPE_FILE);
    return MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(fileId), networkId).ToString();
}
#endif

int MediaFileExtentionUtils::CreateFile(const Uri &parentUri, const string &displayName,  Uri &newFileUri)
{
    if (MediaFileUtils::CheckFileDisplayName(displayName) < 0) {
        MEDIA_ERR_LOG("invalid file displayName %{private}s", displayName.c_str());
        return E_INVALID_DISPLAY_NAME;
    }
    string parentUriStr = parentUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    vector<string> columns = { MEDIA_DATA_DB_FILE_PATH };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, parentUriStr, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_URI_INVALID, "CreateFile parent uri is not correct: %{private}s",
        parentUriStr.c_str());
    string albumPath = GetStringVal(MEDIA_DATA_DB_FILE_PATH, result);
    result->Close();
    string relativePath = albumPath.substr(ROOT_MEDIA_DIR.size()) + SLASH_CHAR;
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    string destPath = albumPath + SLASH_CHAR + displayName;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, MediaFileUtils::GetMediaType(displayName));
    Uri createFileUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_CREATEASSET);
    MediaLibraryCommand cmd(createFileUri);
    ret = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    if (ret > 0) {
        newFileUri = Uri(GetUriFromId(ret, ""));
    }
    return ret;
}

int MediaFileExtentionUtils::Mkdir(const Uri &parentUri, const string &displayName, Uri &newFileUri)
{
    string parentUriStr = parentUri.ToString();
    MediaFileUriType uriType;
    FileAccessFwk::FileInfo parentInfo;
    parentInfo.uri = parentUriStr;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("Mkdir::invalid input fileInfo");
        return ret;
    }
    string relativePath;
    ret = MediaFileExtentionUtils::CheckMkdirValid(uriType, parentUriStr, displayName);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    if (uriType != MediaFileUriType::URI_FILE_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::GetAlbumRelativePathFromDB(parentUriStr, relativePath),
            E_URI_IS_NOT_ALBUM, "selectUri is not valid album uri %{private}s", parentUriStr.c_str());
    }
    Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
    string dirPath = ROOT_MEDIA_DIR + relativePath + displayName;
    if (MediaFileExtentionUtils::IsFileExistInDb(dirPath)) {
        MEDIA_ERR_LOG("Create dir is existed %{private}s", dirPath.c_str());
        return E_FILE_EXIST;
    }
    relativePath = relativePath + displayName + SLASH_CHAR;
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    MediaLibraryCommand cmd(mkdirUri);
    ret = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    if (ret > 0) {
        newFileUri = Uri(GetUriFromId(ret, ""));
    }
    return ret;
}

int MediaFileExtentionUtils::Delete(const Uri &sourceFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    vector<string> columns = { MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_RELATIVE_PATH };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, sourceUri, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_URI_INVALID, "GetResultSetFromDb failed, uri: %{private}s",
        sourceUri.c_str());
#ifdef MEDIALIBRARY_COMPATIBILITY
    string relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
    result->Close();
    if (!MediaFileUtils::IsValidInteger(MediaFileUtils::GetIdFromUri(sourceUri))) {
        return E_URI_INVALID;
    }
    int fileId = stoi(MediaFileUtils::GetIdFromUri(sourceUri));
    DataShareValuesBucket valuesBucket;
    if (mediaType == MEDIA_TYPE_ALBUM) {
#ifdef MEDIALIBRARY_COMPATIBILITY
        valuesBucket.Put(MEDIA_DATA_DB_ID,
            (int) MediaFileUtils::GetRealIdByTable(fileId, MEDIALIBRARY_TABLE));
#else
        valuesBucket.Put(MEDIA_DATA_DB_ID, fileId);
#endif
        Uri trashAlbumUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR +
            MEDIA_DIROPRN_FMS_TRASHDIR);
        MediaLibraryCommand cmd(trashAlbumUri);
        ret = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    } else {
        valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
#ifdef MEDIALIBRARY_COMPATIBILITY
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID,
            (int) MediaFileUtils::GetRealIdByTable(fileId, MEDIALIBRARY_TABLE));
#else
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
#endif
        Uri trashAssetUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_SMARTALBUMMAPOPRN + SLASH_CHAR +
            MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
        MediaLibraryCommand cmd(trashAssetUri);
        ret = MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
    }
    return ret;
}

bool MediaFileExtentionUtils::CheckUriValid(const string &uri)
{
    return MediaFileUri(uri).IsValid();
}

bool MediaFileExtentionUtils::CheckDistributedUri(const string &uri)
{
    string networkId = MediaFileUtils::GetNetworkIdFromUri(uri);
    if (!networkId.empty()) {
        MEDIA_ERR_LOG("not support distributed operation %{private}s", uri.c_str());
        return false;
    }
    return true;
}

int32_t MediaFileExtentionUtils::CheckUriSupport(const string &uri)
{
    if (!MediaFileExtentionUtils::CheckUriValid(uri)) {
        MEDIA_ERR_LOG("Invalid uri");
        return E_URI_INVALID;
    }
    if (!MediaFileExtentionUtils::CheckDistributedUri(uri)) {
        MEDIA_ERR_LOG("CreateFile not support distributed operation");
        return E_DISTIBUTED_URI_NO_SUPPORT;
    }
    return E_SUCCESS;
}

shared_ptr<NativeRdb::ResultSet> MediaFileExtentionUtils::GetResultSetFromDb(string field, const string &value,
    const vector<string> &columns)
{
    string networkId;
    string input = value;
    if (field == MEDIA_DATA_DB_URI) {
        field = MEDIA_DATA_DB_ID;
        networkId = MediaFileUtils::GetNetworkIdFromUri(input);
        input = MediaFileUtils::GetIdFromUri(input);
    }
    Uri queryUri(MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER);
    MediaLibraryCommand cmd(queryUri, OperationType::QUERY);
    DataSharePredicates predicates;
    predicates.EqualTo(field, input)->And()->EqualTo(MEDIA_DATA_DB_IS_TRASH, NOT_TRASHED);
    int errCode = 0;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, nullptr,
        "Failed to obtain value from database, field: %{private}s, value: %{private}s", field.c_str(), input.c_str());
    auto ret = queryResultSet->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == NativeRdb::E_OK, nullptr, "Failed to shift at first row, ret: %{public}d", ret);
    return queryResultSet;
}

bool MediaFileExtentionUtils::IsFileExistInDb(const std::string &path)
{
    vector<string> columns = { MEDIA_DATA_DB_ID };
    return (GetResultSetFromDb(MEDIA_DATA_DB_FILE_PATH, path, columns) != nullptr);
}

int32_t ResolveRootUri(string uri, MediaFileUriType &uriType)
{
    int32_t ret = E_INVALID_URI;
    uri = uri.substr(MEDIALIBRARY_ROOT.length());
    if (uri == MEDIALIBRARY_TYPE_FILE_URI) {
        uriType = MediaFileUriType::URI_FILE_ROOT;
        ret = E_SUCCESS;
    } else if ((uri == MEDIALIBRARY_TYPE_IMAGE_URI) ||
               (uri == MEDIALIBRARY_TYPE_VIDEO_URI) ||
               (uri == MEDIALIBRARY_TYPE_AUDIO_URI)) {
        uriType = MediaFileUriType::URI_MEDIA_ROOT;
        ret = E_SUCCESS;
    }
    return ret;
}

#ifndef MEDIALIBRARY_COMPATIBILITY
int32_t ResolveUriWithType(const string &mimeType, MediaFileUriType &uriType)
{
    if ((mimeType.find(DEFAULT_IMAGE_MIME_TYPE_PREFIX) == 0) ||
        (mimeType.find(DEFAULT_VIDEO_MIME_TYPE_PREFIX) == 0) ||
        (mimeType.find(DEFAULT_AUDIO_MIME_TYPE_PREFIX) == 0)) {
        uriType = MediaFileUriType::URI_ALBUM;
        return E_SUCCESS;
    }
    uriType = MediaFileUriType::URI_DIR;
    return E_SUCCESS;
}
#endif

/**
 * URI_ROOT Return four uri of media type(images, audios, videos and file).
 *  datashare:///media/root
 * URI_MEDIA_ROOT Return all albums of the specified type.
 *  datashare:///media/root/image|audio|video
 * URI_FILE_ROOT Return the files and folders under the root directory.
 *  datashare:///media/root/file
 * URI_DIR Return the files and folders in the directory.
 *  datashare:///media/file/1
 */
int32_t MediaFileExtentionUtils::ResolveUri(const FileInfo &fileInfo, MediaFileUriType &uriType)
{
    MediaFileUri uri(fileInfo.uri);
    string scheme = uri.GetScheme();
    if (scheme != ML_FILE_SCHEME &&
        scheme != ML_DATA_SHARE_SCHEME) {
        return E_INVALID_URI;
    }

    if (uri.ToString().find(MEDIALIBRARY_DATA_URI_IDENTIFIER) == string::npos) {
        return E_INVALID_URI;
    }

    string path = uri.GetPath();
    if (scheme == ML_DATA_SHARE_SCHEME) {
        if (path.length() > MEDIALIBRARY_DATA_URI_IDENTIFIER.length()) {
            path = path.substr(MEDIALIBRARY_DATA_URI_IDENTIFIER.length());
        } else {
            return E_INVALID_URI;
        }
    }

    if (path == MEDIALIBRARY_ROOT) {
        uriType = MediaFileUriType::URI_ROOT;
        return E_SUCCESS;
    }
    if (path.find(MEDIALIBRARY_ROOT) == 0) {
        return ResolveRootUri(path, uriType);
    }
    if (path.find(MEDIALIBRARY_TYPE_FILE_URI) == 0) {
#ifndef MEDIALIBRARY_COMPATIBILITY
        return ResolveUriWithType(fileInfo.mimeType, uriType);
#else
        uriType = MediaFileUriType::URI_DIR;
        return E_SUCCESS;
#endif
    }
    if (MediaFileExtentionUtils::CheckUriValid(fileInfo.uri)) {
        uriType = MediaFileUriType::URI_FILE;
        return E_SUCCESS;
    }

    return E_INVALID_URI;
}

bool MediaFileExtentionUtils::CheckValidDirName(const string &displayName)
{
    for (auto &dir : directoryEnumValues) {
        if (displayName == dir) {
            return true;
        }
    }
    return false;
}

int32_t MediaFileExtentionUtils::CheckMkdirValid(MediaFileUriType uriType, const string &parentUriStr,
    const string &displayName)
{
    if (uriType == MediaFileUriType::URI_FILE_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckDistributedUri(parentUriStr),
            E_DISTIBUTED_URI_NO_SUPPORT, "Mkdir not support distributed operation");
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckValidDirName(displayName + SLASH_CHAR),
            E_INVALID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    } else {
        auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDentryName(displayName) == E_OK,
            E_INVALID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    }
    return E_SUCCESS;
}

bool MediaFileExtentionUtils::GetAlbumRelativePathFromDB(const string &selectUri, string &relativePath)
{
    vector<string> columns = { MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_RELATIVE_PATH };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, selectUri, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "Get album relativePath failed.");
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
    CHECK_AND_RETURN_RET_LOG(mediaType == MEDIA_TYPE_ALBUM, false, "selectUri is not album");
    relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    relativePath += GetStringVal(MEDIA_DATA_DB_NAME, result) + SLASH_CHAR;
    return true;
}

string GetQueryUri(const FileInfo &parentInfo, MediaFileUriType uriType)
{
    string networkId = MediaFileUtils::GetNetworkIdFromUri(parentInfo.uri);
    string queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    if (uriType == URI_MEDIA_ROOT) {
#ifndef MEDIALIBRARY_COMPATIBILITY
        queryUri += SLASH_CHAR + MEDIA_ALBUMOPRN_QUERYALBUM;
#else
        int32_t mediaType = MimeTypeUtils::GetMediaTypeFromMimeType(parentInfo.mimeType);
        switch (mediaType) {
            case MEDIA_TYPE_IMAGE:
            case MEDIA_TYPE_VIDEO:
                queryUri += SLASH_CHAR + MEDIA_PHOTOOPRN + SLASH_CHAR + OPRN_QUERY;
                break;
            case MEDIA_TYPE_AUDIO:
                queryUri += SLASH_CHAR + MEDIA_AUDIOOPRN + SLASH_CHAR + OPRN_QUERY;
                break;
            case MEDIA_TYPE_FILE:
            default:
                MEDIA_ERR_LOG("GetMediaTypeFromMimeType failed");
                break;
        }
        MediaFileUtils::UriAppendKeyValue(queryUri, URI_PARAM_API_VERSION);
#endif
    }
    return queryUri;
}

void ChangeToLowerCase(vector<string> &vec)
{
    for (auto &s : vec) {
        transform(s.begin(), s.end(), s.begin(), ::tolower);
    }
}

int32_t GetListFilePredicates(const FileInfo &parentInfo, const FileAccessFwk::FileFilter &filter, string &selection,
    vector<string> &selectionArgs)
{
    string selectUri = parentInfo.uri;
    if (!MediaFileExtentionUtils::CheckUriValid(selectUri)) {
        MEDIA_ERR_LOG("selectUri is not valid uri %{private}s", selectUri.c_str());
        return E_URI_INVALID;
    }
    string relativePath;
    if (!MediaFileExtentionUtils::GetAlbumRelativePathFromDB(selectUri, relativePath)) {
        MEDIA_ERR_LOG("selectUri is not valid album uri %{private}s", selectUri.c_str());
        return E_URI_IS_NOT_ALBUM;
    }
    selection = MEDIA_DATA_DB_RELATIVE_PATH + " = ? AND " + MEDIA_DATA_DB_IS_TRASH + " = ? ";
    selectionArgs = { relativePath, to_string(NOT_TRASHED) };
    if (!filter.GetHasFilter()) {
        return E_SUCCESS;
    }
    vector<string> displayName = filter.GetDisplayName();
    ChangeToLowerCase(displayName);
    if (!displayName.empty()) {
        selection += " AND (" + MEDIA_DATA_DB_TITLE + " = ? ";
        selectionArgs.push_back(displayName[0]);
        for (size_t i = 1; i < displayName.size(); i++) {
            selection += " OR " + MEDIA_DATA_DB_TITLE + " = ? ";
            selectionArgs.push_back(displayName[i]);
        }
        selection += ") ";
    }
    vector<string> suffix = filter.GetSuffix();
    ChangeToLowerCase(suffix);
    if (!suffix.empty()) {
        selection += " AND ( " + MEDIA_DATA_DB_NAME + " LIKE ? ";
        selectionArgs.push_back("%" + suffix[0]);
        for (size_t i = 1; i < suffix.size(); i++) {
            selection += " OR " + MEDIA_DATA_DB_NAME + " LIKE ? ";
            selectionArgs.push_back("%" + suffix[i]);
        }
        selection += ") ";
    }
    return E_SUCCESS;
}

static int32_t RootListFile(const FileInfo &parentInfo, vector<FileInfo> &fileList)
{
    string selectUri = parentInfo.uri;
    fileList.emplace_back(selectUri + MEDIALIBRARY_TYPE_FILE_URI, "", "MEDIA_TYPE_FILE", ALBUM_MODE_READONLY,
        DEFAULT_FILE_MIME_TYPE);
    fileList.emplace_back(selectUri + MEDIALIBRARY_TYPE_IMAGE_URI, "", "MEDIA_TYPE_IMAGE", ALBUM_MODE_READONLY,
        DEFAULT_IMAGE_MIME_TYPE);
    fileList.emplace_back(selectUri + MEDIALIBRARY_TYPE_VIDEO_URI, "", "MEDIA_TYPE_VIDEO", ALBUM_MODE_READONLY,
        DEFAULT_VIDEO_MIME_TYPE);
    fileList.emplace_back(selectUri + MEDIALIBRARY_TYPE_AUDIO_URI, "", "MEDIA_TYPE_AUDIO", ALBUM_MODE_READONLY,
        DEFAULT_AUDIO_MIME_TYPE);
    return E_SUCCESS;
}

shared_ptr<NativeRdb::ResultSet> GetResult(const Uri &uri, MediaFileUriType uriType, const string &selection,
    const vector<string> &selectionArgs)
{
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    int errCode = 0;
    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_SIZE, MEDIA_DATA_DB_DATE_ADDED,
        MEDIA_DATA_DB_DATE_MODIFIED, MEDIA_DATA_DB_MIME_TYPE, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_RELATIVE_PATH };
    return MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
}

static string MimeType2MediaType(const string &mimeType)
{
    // album view not support file type, so image as default
    int res = MEDIA_TYPE_IMAGE;
    if (mimeType.find(DEFAULT_VIDEO_MIME_TYPE_PREFIX) == 0) {
        res = MEDIA_TYPE_VIDEO;
    } else if (mimeType.find(DEFAULT_AUDIO_MIME_TYPE_PREFIX) == 0) {
        res = MEDIA_TYPE_AUDIO;
    }
    return to_string(res);
}

shared_ptr<NativeRdb::ResultSet> GetMediaRootResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount)
{
#ifndef MEDIALIBRARY_COMPATIBILITY
    Uri uri(GetQueryUri(parentInfo, uriType));
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, MimeType2MediaType(parentInfo.mimeType));
    predicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_TRASHED));
    predicates.Limit(maxCount, offset);
    int errCode = 0;
    vector<string> columns = { MEDIA_DATA_DB_BUCKET_ID, MEDIA_DATA_DB_TITLE, MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_RELATIVE_PATH };
#else
    Uri uri(GetQueryUri(parentInfo, uriType));
    DataSharePredicates predicates;
    predicates.EqualTo(MediaColumn::MEDIA_TYPE, MimeType2MediaType(parentInfo.mimeType));
    predicates.EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(NOT_TRASHED));
    if ((MimeTypeUtils::GetMediaTypeFromMimeType(parentInfo.mimeType) == MEDIA_TYPE_IMAGE) ||
        (MimeTypeUtils::GetMediaTypeFromMimeType(parentInfo.mimeType) == MEDIA_TYPE_VIDEO)) {
        predicates.EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    }
    predicates.Limit(maxCount, offset);
    int errCode = 0;
    vector<string> columns = { MediaColumn::MEDIA_RELATIVE_PATH, MediaColumn::MEDIA_NAME, MediaColumn::MEDIA_ID,
        MediaColumn::MEDIA_DATE_MODIFIED };
#endif
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    return MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
}

shared_ptr<NativeRdb::ResultSet> GetListRootResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount)
{
#ifndef MEDIALIBRARY_COMPATIBILITY
    string selection = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? AND " +
        MEDIA_DATA_DB_IS_TRASH + " = ? LIMIT " + to_string(offset) + ", " + to_string(maxCount);
    vector<string> selectionArgs = { to_string(ROOT_PARENT_ID), to_string(MEDIA_TYPE_NOFILE), to_string(NOT_TRASHED) };
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
#else
    string selection = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? AND " +
        MEDIA_DATA_DB_IS_TRASH + " = ? LIMIT " + to_string(offset) + ", " + to_string(maxCount);
    vector<string> selectionArgs = { to_string(ROOT_PARENT_ID), to_string(MEDIA_TYPE_ALBUM), to_string(NOT_TRASHED) };
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
#endif
}

shared_ptr<NativeRdb::ResultSet> GetListDirResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const FileAccessFwk::FileFilter &filter)
{
    string selection;
    vector<string> selectionArgs;
    int32_t ret = GetListFilePredicates(parentInfo, filter, selection, selectionArgs);
    if (ret != E_SUCCESS) {
        return nullptr;
    }
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? LIMIT " + to_string(offset) + ", " + to_string(maxCount);
    selectionArgs.push_back(to_string(MEDIA_TYPE_NOFILE));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
}

#ifndef MEDIALIBRARY_COMPATIBILITY
shared_ptr<NativeRdb::ResultSet> GetListAlbumResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const FileAccessFwk::FileFilter &filter)
{
    string selection;
    vector<string> selectionArgs;
    int32_t ret = GetListFilePredicates(parentInfo, filter, selection, selectionArgs);
    if (ret != E_SUCCESS) {
        return nullptr;
    }
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? LIMIT " + to_string(offset) + ", " + to_string(maxCount);
    selectionArgs.push_back(MimeType2MediaType(parentInfo.mimeType));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
}
#endif

int GetFileInfo(FileInfo &fileInfo, const shared_ptr<NativeRdb::ResultSet> &result, const string &networkId = "")
{
    int64_t fileId = GetInt32Val(MEDIA_DATA_DB_ID, result);
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
#ifdef MEDIALIBRARY_COMPATIBILITY
    fileId = MediaFileUtils::GetVirtualIdByType(fileId, MediaType::MEDIA_TYPE_FILE);
    fileInfo.uri = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(fileId), networkId).ToString();
#else
    fileInfo.uri = MediaFileUri(MediaType(mediaType), to_string(fileId), networkId).ToString();
#endif
    fileInfo.relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    fileInfo.fileName = GetStringVal(MEDIA_DATA_DB_NAME, result);
    fileInfo.mimeType = GetStringVal(MEDIA_DATA_DB_MIME_TYPE, result);
    if (mediaType == MEDIA_TYPE_ALBUM) {
        fileInfo.mode = ALBUM_MODE_RW;
    } else {
        fileInfo.size = GetInt64Val(MEDIA_DATA_DB_SIZE, result);
        fileInfo.mode = FILE_MODE_RW;
    }
    fileInfo.mtime = GetInt64Val(MEDIA_DATA_DB_DATE_MODIFIED, result);
    return E_SUCCESS;
}

#ifndef MEDIALIBRARY_COMPATIBILITY
int32_t GetAlbumInfoFromResult(const FileInfo &parentInfo, shared_ptr<NativeRdb::ResultSet> &result,
    vector<FileInfo> &fileList)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "ResultSet is nullptr");
    string networkId = MediaFileUtils::GetNetworkIdFromUri(parentInfo.uri);
    FileInfo fileInfo;
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int fileId = GetInt32Val(MEDIA_DATA_DB_BUCKET_ID, result);
        fileInfo.fileName = GetStringVal(MEDIA_DATA_DB_TITLE, result);
        fileInfo.mimeType = parentInfo.mimeType;
        fileInfo.uri = MediaFileUri(MEDIA_TYPE_ALBUM, to_string(fileId), networkId).ToString();
        fileInfo.relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
        fileInfo.mtime = GetInt64Val(MEDIA_DATA_DB_DATE_MODIFIED, result);
        fileInfo.mode = ALBUM_MODE_RW;
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}
#else
int32_t GetMediaFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<NativeRdb::ResultSet> &result,
    vector<FileInfo> &fileList)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "ResultSet is nullptr");
    FileInfo fileInfo;
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int fileId = GetInt32Val(MediaColumn::MEDIA_ID, result);
        fileInfo.fileName = GetStringVal(MEDIA_DATA_DB_TITLE, result);
        fileInfo.mimeType = parentInfo.mimeType;
        fileInfo.uri = MediaFileUri(MEDIA_TYPE_ALBUM, to_string(fileId), "").ToString();
        fileInfo.relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
        fileInfo.mtime = GetInt64Val(MEDIA_DATA_DB_DATE_MODIFIED, result);
        fileInfo.mode = ALBUM_MODE_RW;
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}
#endif

#ifndef MEDIALIBRARY_COMPATIBILITY
int32_t GetFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<NativeRdb::ResultSet> &result,
    vector<FileInfo> &fileList)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "ResultSet is nullptr");
    string networkId = MediaFileUtils::GetNetworkIdFromUri(parentInfo.uri);
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        GetFileInfo(fileInfo, result, networkId);
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}
#else
int32_t GetFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<NativeRdb::ResultSet> &result,
    vector<FileInfo> &fileList, MediaFileUriType uriType)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "ResultSet is nullptr");
    string networkId = MediaFileUtils::GetNetworkIdFromUri(parentInfo.uri);
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        GetFileInfo(fileInfo, result, networkId);
        switch (uriType) {
            case URI_FILE_ROOT:
                if (fileInfo.relativePath == "" && (fileInfo.fileName == "Documents" ||
                    fileInfo.fileName == "Download")) {
                    fileList.push_back(fileInfo);
                }
                break;
            case URI_DIR:
                fileList.push_back(fileInfo);
                break;
            default:
                return E_FAIL;
        }
    }
    return E_SUCCESS;
}
#endif

int32_t MediaFileExtentionUtils::ListFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const FileAccessFwk::FileFilter &filter, vector<FileInfo> &fileList)
{
    MediaFileUriType uriType;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    MEDIA_DEBUG_LOG("ListFile:: uriType: %d", uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("ResolveUri::invalid input fileInfo");
        return ret;
    }
    shared_ptr<NativeRdb::ResultSet> result = nullptr;
    switch (uriType) {
        case URI_ROOT:
            return RootListFile(parentInfo, fileList);
#ifndef MEDIALIBRARY_COMPATIBILITY
        case URI_MEDIA_ROOT:
            result = GetMediaRootResult(parentInfo, uriType, offset, maxCount);
            return GetAlbumInfoFromResult(parentInfo, result, fileList);
        case URI_FILE_ROOT:
            result = GetListRootResult(parentInfo, uriType, offset, maxCount);
            return GetFileInfoFromResult(parentInfo, result, fileList);
        case URI_DIR:
            result = GetListDirResult(parentInfo, uriType, offset, maxCount, filter);
            return GetFileInfoFromResult(parentInfo, result, fileList);
        case URI_ALBUM:
            result = GetListAlbumResult(parentInfo, uriType, offset, maxCount, filter);
            return GetFileInfoFromResult(parentInfo, result, fileList);
#else
        case URI_MEDIA_ROOT:
            result = GetMediaRootResult(parentInfo, uriType, offset, maxCount);
            return GetMediaFileInfoFromResult(parentInfo, result, fileList);
        case URI_FILE_ROOT:
            result = GetListRootResult(parentInfo, uriType, offset, maxCount);
            return GetFileInfoFromResult(parentInfo, result, fileList, uriType);
        case URI_DIR:
            result = GetListDirResult(parentInfo, uriType, offset, maxCount, filter);
            return GetFileInfoFromResult(parentInfo, result, fileList, uriType);
#endif
        default:
            return E_FAIL;
    }
}

int32_t GetScanFileFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<NativeRdb::ResultSet> &result,
    vector<FileInfo> &fileList)
{
#ifndef MEDIALIBRARY_COMPATIBILITY
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "the result is nullptr");
#else
    if (result == nullptr) {
        return E_ERR;
    }
#endif
    string networkId = MediaFileUtils::GetNetworkIdFromUri(parentInfo.uri);
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        GetFileInfo(fileInfo, result, networkId);
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}

shared_ptr<NativeRdb::ResultSet> GetScanFileResult(const Uri &uri, MediaFileUriType uriType, const string &selection,
    const vector<string> &selectionArgs)
{
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    int errCode  = 0;
    vector<string> columns {
        MEDIA_DATA_DB_BUCKET_ID,
        MEDIA_DATA_DB_TITLE,
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_SIZE,
        MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_MIME_TYPE,
        MEDIA_DATA_DB_NAME,
        MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_RELATIVE_PATH
    };
    return MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
}

shared_ptr<NativeRdb::ResultSet> SetScanFileSelection(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const FileAccessFwk::FileFilter &filter)
{
    string filePath;
    vector<string> selectionArgs;
    if (uriType == MediaFileUriType::URI_ROOT) {
        filePath = ROOT_MEDIA_DIR;
        selectionArgs.push_back(filePath + "%");
    } else {
        vector<string> columns = { MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_RELATIVE_PATH };
        auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, parentInfo.uri, columns);
        CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "Get file path failed, uri: %{private}s",
            parentInfo.uri.c_str());
        filePath = GetStringVal(MEDIA_DATA_DB_FILE_PATH, result);
        selectionArgs.push_back(filePath + "/%");
#ifdef MEDIALIBRARY_COMPATIBILITY
        string relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
        if (!CheckDestRelativePath(relativePath)) {
            return nullptr;
        }
#endif
    }
    MEDIA_DEBUG_LOG("ScanFile filepath: %{private}s", filePath.c_str());
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? ";
    if (filter.GetSuffix().size() > 0) {
        selection += " AND ( " + Media::MEDIA_DATA_DB_NAME + " LIKE ? ";
        selectionArgs.emplace_back("%" + filter.GetSuffix()[0]);
    }
    for (size_t i = 1; i < filter.GetSuffix().size(); i++) {
        selection += " OR " + Media::MEDIA_DATA_DB_NAME + " LIKE ? ";
        selectionArgs.emplace_back("%" + filter.GetSuffix()[i]);
    }
    if (filter.GetSuffix().size() > 0) {
        selection += ")";
    }
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_NOFILE);
    selection += " AND " + MEDIA_DATA_DB_IS_TRASH + " = ? LIMIT " + to_string(offset) + ", " + to_string(maxCount);
    selectionArgs.push_back(to_string(NOT_TRASHED));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetScanFileResult(uri, uriType, selection, selectionArgs);
}

int32_t MediaFileExtentionUtils::ScanFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const FileAccessFwk::FileFilter &filter, vector<FileInfo> &fileList)
{
    MediaFileUriType uriType;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    MEDIA_DEBUG_LOG("ScanFile:: uriType: %d", uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("ResolveUri::invalid input fileInfo");
        return ret;
    }
    auto result = SetScanFileSelection(parentInfo, uriType, offset, maxCount, filter);
    return GetScanFileFileInfoFromResult(parentInfo, result, fileList);
}

static int QueryDirSize(FileInfo fileInfo)
{
    vector<FileInfo> fileInfoVec;
    FileAccessFwk::FileFilter filter;
    int64_t offset { 0 };
    int32_t ret = E_ERR;
    int64_t size = 0;
    do {
        fileInfoVec.clear();
        ret = MediaFileExtentionUtils::ScanFile(fileInfo, offset, MAX_COUNT, filter, fileInfoVec);
        if (ret != E_SUCCESS) {
            MEDIA_ERR_LOG("ScanFile get result error, code:%{public}d", ret);
            return ret;
        }
        for (auto info : fileInfoVec) {
            size += info.size;
        }
        offset += MAX_COUNT;
    } while (fileInfoVec.size() == MAX_COUNT);
    return size;
}

int32_t MediaFileExtentionUtils::Query(const Uri &uri, std::vector<std::string> &columns,
    std::vector<std::string> &results)
{
    string queryUri = uri.ToString();
    if (!CheckUriValid(queryUri)) {
        return E_URI_INVALID;
    }

    bool isExist = false;
    int ret = Access(uri, isExist);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "Access uri error, code:%{public}d", ret);
    CHECK_AND_RETURN_RET(isExist, E_NO_SUCH_FILE);

    auto resultSet = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, queryUri, columns);
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, E_URI_INVALID, "Get resultSet failed, uri: %{private}s",
        queryUri.c_str());
    for (auto column : columns) {
        if (column == MEDIA_DATA_DB_SIZE) {
            FileInfo fileInfo;
            int ret = GetFileInfoFromUri(uri, fileInfo);
            CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "Get fileInfo from uri error, code:%{public}d", ret);
            if (fileInfo.mode & DOCUMENT_FLAG_REPRESENTS_DIR) {
                ret = QueryDirSize(fileInfo);
                CHECK_AND_RETURN_RET_LOG(ret >= 0, ret, "Query directory size error, code:%{public}d", ret);
                results.push_back(std::to_string(ret));
                continue;
            }
        }
        auto memberType = FILE_RESULT_TYPE.at(column);
        switch (memberType) {
            case STRING_TYPE:
                results.push_back(GetStringVal(column, resultSet));
                break;
            case INT32_TYPE:
                results.push_back(std::to_string(GetInt32Val(column, resultSet)));
                break;
            case INT64_TYPE:
                results.push_back(std::to_string(GetInt64Val(column, resultSet)));
                break;
            default:
                MEDIA_ERR_LOG("not match  memberType %{public}d", memberType);
                break;
        }
    }
    resultSet->Close();
    return E_SUCCESS;
}

bool GetRootInfo(shared_ptr<NativeRdb::ResultSet> &result, RootInfo &rootInfo)
{
    string networkId = GetStringVal(DEVICE_DB_NETWORK_ID, result);
    rootInfo.uri = ML_FILE_URI_PREFIX + "/" + networkId + MEDIALIBRARY_ROOT;
    rootInfo.displayName = GetStringVal(DEVICE_DB_NAME, result);
    rootInfo.deviceFlags = DEVICE_FLAG_SUPPORTS_READ;
    rootInfo.deviceType = DEVICE_SHARED_TERMINAL;
    return true;
}

void GetRootInfoFromResult(shared_ptr<NativeRdb::ResultSet> &result, vector<RootInfo> &rootList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_LOG(count > 0, "ResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_LOG(ret == 0, "Failed to shift at first row");
    rootList.reserve(count + 1);
    for (int i = 0; i < count; i++) {
        RootInfo rootInfo;
        GetRootInfo(result, rootInfo);
        rootList.push_back(rootInfo);
        ret = result->GoToNextRow();
        CHECK_AND_RETURN_LOG(ret == 0, "Failed to GoToNextRow");
    }
}

void GetActivePeer(shared_ptr<NativeRdb::ResultSet> &result)
{
    string strQueryCondition = DEVICE_DB_DATE_MODIFIED + " = 0";
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(strQueryCondition);
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    int errCode = 0;
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
}

int32_t MediaFileExtentionUtils::GetRoots(vector<RootInfo> &rootList)
{
    return E_SUCCESS;
}

int MediaFileExtentionUtils::Access(const Uri &uri, bool &isExist)
{
    isExist = false;
    string sourceUri = uri.ToString();
    CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckUriValid(sourceUri), E_URI_INVALID,
        "Access::invalid uri: %{private}s", sourceUri.c_str());
    vector<string> columns = { MEDIA_DATA_DB_ID };
    auto result = GetResultSetFromDb(MEDIA_DATA_DB_URI, sourceUri, columns);
    if (result == nullptr) {
        MEDIA_ERR_LOG("Access::uri is not correct: %{private}s", sourceUri.c_str());
        return E_INVALID_URI;
    }
    isExist = true;
    return E_SUCCESS;
}

int GetVirtualNodeFileInfo(const string &uri, FileInfo &fileInfo)
{
    size_t pos = uri.rfind('/');
    if (pos == string::npos) {
        return E_INVALID_URI;
    }

    static const unordered_map<string, FileInfo> virtualNodes = {
        { MEDIALIBRARY_TYPE_AUDIO_URI, { uri, "", "MEDIA_TYPE_AUDIO", ALBUM_MODE_READONLY, DEFAULT_AUDIO_MIME_TYPE } },
        { MEDIALIBRARY_TYPE_VIDEO_URI, { uri, "", "MEDIA_TYPE_VIDEO", ALBUM_MODE_READONLY, DEFAULT_VIDEO_MIME_TYPE } },
        { MEDIALIBRARY_TYPE_IMAGE_URI, { uri, "", "MEDIA_TYPE_IMAGE", ALBUM_MODE_READONLY, DEFAULT_IMAGE_MIME_TYPE } },
        { MEDIALIBRARY_TYPE_FILE_URI, { uri, "", "MEDIA_TYPE_FILE", ALBUM_MODE_READONLY, DEFAULT_FILE_MIME_TYPE } },
    };
    string uriSuffix = uri.substr(pos);
    if (virtualNodes.find(uriSuffix) != virtualNodes.end()) {
        fileInfo = virtualNodes.at(uriSuffix);
        return E_SUCCESS;
    } else {
        return E_INVALID_URI;
    }
}

int MediaFileExtentionUtils::GetThumbnail(const Uri &uri, const Size &size, std::unique_ptr<PixelMap> &pixelMap)
{
    string queryUriStr = uri.ToString();
    if (!CheckUriValid(queryUriStr)) {
        MEDIA_ERR_LOG("GetThumbnail::invalid uri: %{private}s", queryUriStr.c_str());
        return E_URI_INVALID;
    }
#ifdef MEDIALIBRARY_COMPATIBILITY
    string realUri = MediaFileUtils::GetRealUriFromVirtualUri(queryUriStr);
    string pixelMapUri = realUri + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        MEDIA_DATA_DB_WIDTH + "=" + std::to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" +
        std::to_string(size.height);
#else
    string pixelMapUri = queryUriStr + "?" + MEDIA_OPERN_KEYWORD + "=" + MEDIA_DATA_DB_THUMBNAIL + "&" +
        MEDIA_DATA_DB_WIDTH + "=" + std::to_string(size.width) + "&" + MEDIA_DATA_DB_HEIGHT + "=" +
        std::to_string(size.height);
#endif
    UniqueFd uniqueFd(MediaLibraryDataManager::GetInstance()->GetThumbnail(pixelMapUri));
    if (uniqueFd.Get() < 0) {
        MEDIA_ERR_LOG("queryThumb is null, errCode is %{public}d", uniqueFd.Get());
        return E_FAIL;
    }
    uint32_t err = 0;
    SourceOptions opts;
    unique_ptr<ImageSource> imageSource = ImageSource::CreateImageSource(uniqueFd.Get(), opts, err);
    if (imageSource  == nullptr) {
        MEDIA_ERR_LOG("CreateImageSource err %{public}d", err);
        return E_FAIL;
    }
    DecodeOptions decodeOpts;
    decodeOpts.desiredSize = size;
    pixelMap = imageSource->CreatePixelMap(decodeOpts, err);
    return E_OK;
}

int MediaFileExtentionUtils::GetFileInfoFromUri(const Uri &selectFile, FileInfo &fileInfo)
{
    string uri = selectFile.ToString();
    MediaFileUriType uriType = URI_FILE;

    FileInfo tempInfo;
    tempInfo.uri = uri;
    tempInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    auto ret = MediaFileExtentionUtils::ResolveUri(tempInfo, uriType);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "GetFileInfoFromUri::invalid uri: %{private}s", uri.c_str());

    switch (uriType) {
        case URI_ROOT:
            fileInfo.uri = uri;
            return E_SUCCESS;
        case URI_MEDIA_ROOT:
        case URI_FILE_ROOT:
            return GetVirtualNodeFileInfo(uri, fileInfo);
        case URI_DIR:
        case URI_ALBUM:
        case URI_FILE: {
            vector<string> columns = FILEINFO_COLUMNS;
            auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, uri, columns);
            CHECK_AND_RETURN_RET_LOG(result != nullptr, E_INVALID_URI,
                "GetFileInfoFromUri::uri is not correct: %{private}s", uri.c_str());
            const string networkId = MediaFileUtils::GetNetworkIdFromUri(uri);
            return GetFileInfo(fileInfo, result, networkId);
        }
        default:
            return E_INVALID_URI;
    }
}

int MediaFileExtentionUtils::GetFileInfoFromRelativePath(const string &relativePath, FileAccessFwk::FileInfo &fileInfo)
{
    if (relativePath.empty()) {
        fileInfo = { MEDIALIBRARY_DATA_URI + MEDIALIBRARY_TYPE_FILE_URI, "", "MEDIA_TYPE_FILE", ALBUM_MODE_READONLY,
            DEFAULT_FILE_MIME_TYPE };
        return E_SUCCESS;
    }

    string path = ROOT_MEDIA_DIR + relativePath;
    if (path.back() == '/') {
        path.pop_back();
    }
    vector<string> columns = FILEINFO_COLUMNS;
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_FILE_PATH, path, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_NO_SUCH_FILE,
        "GetFileInfoFromRelativePath::Get FileInfo failed, relativePath: %{private}s", relativePath.c_str());
    return GetFileInfo(fileInfo, result);
}

int32_t HandleFileRename(const shared_ptr<FileAsset> &fileAsset)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
#ifdef MEDIALIBRARY_COMPATIBILITY
    string fileUri = fileAsset->GetUri() + SLASH_CHAR + to_string(MediaFileUtils::GetVirtualIdByType(
        fileAsset->GetId(), MediaType::MEDIA_TYPE_FILE));
#else
    string fileUri = fileAsset->GetUri() + SLASH_CHAR + to_string(fileAsset->GetId());
#endif
    valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, fileAsset->GetRelativePath());
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileAsset->GetId()) });
    MediaLibraryCommand cmd(updateAssetUri);
    auto ret = MediaLibraryDataManager::GetInstance()->Update(cmd, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileRename Update ret %{public}d", ret);
        return ret;
    }
}

string GetRelativePathFromPath(const string &path)
{
    string relativePath = "";
    if (path.length() > ROOT_MEDIA_DIR.length()) {
        relativePath = path.substr(ROOT_MEDIA_DIR.length());
    }
    return relativePath;
}

int32_t UpdateRenamedAlbumInfo(const string &srcId, const string &displayName, const string &newAlbumPath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, srcId);
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    valuesBucket.PutString(MEDIA_DATA_DB_TITLE, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.PutString(MEDIA_DATA_DB_BUCKET_NAME, displayName);
    int32_t count = 0;
    return MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count, valuesBucket, absPredicates);
}

int32_t UpdateSubFilesPath(const string &srcPath, const string &newAlbumPath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
    // Update data "old albumPath/%" -> "new albumPath/%"
    modifySql += MEDIA_DATA_DB_FILE_PATH + " = replace("
        + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), ";
    // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
    modifySql += MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
        + ", '" + GetRelativePathFromPath(srcPath) + "/', '" + GetRelativePathFromPath(newAlbumPath) + "/'), ";
    // Update date_modified "old time" -> "new time"
    modifySql += MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified);
    modifySql += " WHERE " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%' AND " +
        MEDIA_DATA_DB_IS_TRASH + " = " + to_string(NOT_TRASHED);
    MEDIA_DEBUG_LOG("UpdateSubFilesPath modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t UpdateSubFilesBucketName(const string &srcId, const string &displayName)
{
    // Update bucket_display_name "old album displayName" -> "new album displayName"
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_BUCKET_NAME + " = '" + displayName;
    modifySql += "' WHERE " + MEDIA_DATA_DB_PARENT_ID + " = " + srcId + " AND " +
        MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM) + " AND " +
        MEDIA_DATA_DB_IS_TRASH + " = " + to_string(NOT_TRASHED);
    MEDIA_DEBUG_LOG("UpdateSubFilesBucketName modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t HandleAlbumRename(const shared_ptr<FileAsset> &fileAsset)
{
    if (fileAsset->GetRelativePath().empty()) {
        MEDIA_ERR_LOG("Rename dir in root dir, denied");
        return E_DENIED_RENAME;
    }
    string srcPath = fileAsset->GetPath();
    size_t slashIndex = srcPath.rfind(SLASH_CHAR);
    string destPath = srcPath.substr(0, slashIndex) + SLASH_CHAR + fileAsset->GetDisplayName();
    if (MediaFileExtentionUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Rename file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    bool succ = MediaFileUtils::RenameDir(srcPath, destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }
    // update parent info
    string parentPath = ROOT_MEDIA_DIR + fileAsset->GetRelativePath();
    parentPath.pop_back();
    MediaLibraryObjectUtils::UpdateDateModified(parentPath);

    // update album info
    string srcId = to_string(fileAsset->GetId());
    int32_t updateResult = UpdateRenamedAlbumInfo(srcId, fileAsset->GetDisplayName(), destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateRenamedAlbumInfo failed");

    // update child info
    updateResult = UpdateSubFilesPath(srcPath, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    updateResult = UpdateSubFilesBucketName(srcId, fileAsset->GetDisplayName());
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL,
        "UpdateSubFilesBucketName failed");
    return E_SUCCESS;
}

int32_t MediaFileExtentionUtils::Rename(const Uri &sourceFileUri, const string &displayName, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_URI, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_MEDIA_TYPE,
        MEDIA_DATA_DB_RELATIVE_PATH };
    auto result = GetResultSetFromDb(MEDIA_DATA_DB_URI, sourceUri, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_MODIFY_DATA_FAIL, "Rename source uri is not correct %{private}s",
        sourceUri.c_str());

    auto fileAsset = make_shared<FileAsset>();
    fileAsset->SetId(GetInt32Val(MEDIA_DATA_DB_ID, result));
    fileAsset->SetUri(GetStringVal(MEDIA_DATA_DB_URI, result));
    fileAsset->SetPath(GetStringVal(MEDIA_DATA_DB_FILE_PATH, result));
    fileAsset->SetDisplayName(displayName);
    fileAsset->SetMediaType(static_cast<MediaType>(GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result)));
#ifdef MEDIALIBRARY_COMPATIBILITY
    string relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    fileAsset->SetRelativePath(GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result));
    result->Close();

    if (fileAsset->GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        if (MediaFileUtils::CheckDentryName(displayName) < 0) {
            MEDIA_ERR_LOG("invalid albumName %{private}s", displayName.c_str());
            return E_INVALID_DISPLAY_NAME;
        }
        ret = HandleAlbumRename(fileAsset);
    } else {
        if (MediaFileUtils::CheckFileDisplayName(displayName) < 0) {
            MEDIA_ERR_LOG("invalid displayName %{private}s", displayName.c_str());
            return E_INVALID_DISPLAY_NAME;
        }
        ret = HandleFileRename(fileAsset);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}

int32_t HandleFileMove(const shared_ptr<FileAsset> &fileAsset, const string &destRelativePath)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAsset->GetMediaType());
#ifdef MEDIALIBRARY_COMPATIBILITY
    string fileUri = fileAsset->GetUri() + SLASH_CHAR + to_string(MediaFileUtils::GetVirtualIdByType(
        fileAsset->GetId(), MediaType::MEDIA_TYPE_FILE));
#else
    string fileUri = fileAsset->GetUri() + SLASH_CHAR + to_string(fileAsset->GetId());
#endif
    valuesBucket.Put(MEDIA_DATA_DB_URI, fileUri);
    valuesBucket.Put(MEDIA_DATA_DB_NAME, fileAsset->GetDisplayName());
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ to_string(fileAsset->GetId()) });
    MediaLibraryCommand cmd(updateAssetUri);
    auto ret = MediaLibraryDataManager::GetInstance()->Update(cmd, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileMove Update ret %{public}d", ret);
        return ret;
    }
}

int32_t UpdateMovedAlbumInfo(const shared_ptr<FileAsset> &fileAsset, const string &bucketId, const string &newAlbumPath,
    const string &destRelativePath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, to_string(fileAsset->GetId()));
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    if (MediaFileUtils::IsValidInteger(bucketId)) {
        valuesBucket.PutInt(MEDIA_DATA_DB_PARENT_ID, stoi(bucketId));
        valuesBucket.PutInt(MEDIA_DATA_DB_BUCKET_ID, stoi(bucketId));
    }
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    int32_t count = 0;
    return MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count, valuesBucket, absPredicates);
}

int32_t HandleAlbumMove(const shared_ptr<FileAsset> &fileAsset, const string &destRelativePath, const string &bucketId)
{
    string destPath = ROOT_MEDIA_DIR + destRelativePath + fileAsset->GetDisplayName();
    if (MediaFileExtentionUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Move file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    string srcPath = fileAsset->GetPath();
    bool succ = MediaFileUtils::RenameDir(srcPath, destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }
    // update parent info
    string srcParentPath = ROOT_MEDIA_DIR + fileAsset->GetRelativePath();
    srcParentPath.pop_back();
    string destParentPath = ROOT_MEDIA_DIR + destRelativePath;
    destParentPath.pop_back();
    MediaLibraryObjectUtils::UpdateDateModified(srcParentPath);
    MediaLibraryObjectUtils::UpdateDateModified(destParentPath);

    // update album info
    int32_t updateResult = UpdateMovedAlbumInfo(fileAsset, bucketId, destPath, destRelativePath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateMovedAlbumInfo failed");

    // update child info
    updateResult = UpdateSubFilesPath(srcPath, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    return E_SUCCESS;
}

void GetMoveSubFile(const string &srcPath, shared_ptr<NativeRdb::ResultSet> &result)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? ";
    vector<string> selectionArgs = { srcPath + SLASH_CHAR + "%" };
    vector<string> columns = { MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_MEDIA_TYPE };
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    MediaLibraryCommand cmd(uri, OperationType::QUERY);
    int errCode = 0;
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(cmd, columns, predicates, errCode);
}

bool CheckSubFileExtension(const string &srcPath, const string &destRelPath)
{
    shared_ptr<NativeRdb::ResultSet> result;
    GetMoveSubFile(srcPath, result);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, true, "ResultSet empty");
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int32_t mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
        string path = GetStringVal(MEDIA_DATA_DB_FILE_PATH, result);
        string name = GetStringVal(MEDIA_DATA_DB_NAME, result);
        if (mediaType == MEDIA_TYPE_ALBUM) {
            continue;
        }
        if (MediaLibraryObjectUtils::CheckDirExtension(destRelPath, name) != E_SUCCESS) {
            return false;
        }
    }
    return true;
}

bool CheckRootDir(const shared_ptr<FileAsset> &fileAsset, const string &destRelPath)
{
    string srcRelPath = fileAsset->GetRelativePath();
    if (srcRelPath.empty()) {
        MEDIA_ERR_LOG("Can not move the first level directories, like Pictures, Audios, ...");
        return false;
    }
    if (destRelPath.empty()) {
        MEDIA_ERR_LOG("Can not move to root dir");
        return false;
    }
    size_t srcPos = srcRelPath.find(SLASH_CHAR);
    size_t destPos = destRelPath.find(SLASH_CHAR);
    if (srcPos == string::npos || destPos == string::npos) {
        MEDIA_ERR_LOG("Invalid relativePath %{private}s, %{private}s", srcRelPath.c_str(), destRelPath.c_str());
        return false;
    }
    if (srcRelPath.substr(0, srcPos) != destRelPath.substr(0, destPos)) {
        MEDIA_INFO_LOG("move dir to other root dir");
        return CheckSubFileExtension(fileAsset->GetPath(), destRelPath);
    }
    return true;
}

int32_t MediaFileExtentionUtils::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    string targetUri = targetParentUri.ToString();
    CHECK_AND_RETURN_RET_LOG(sourceUri != targetUri, E_TWO_URI_ARE_THE_SAME,
        "sourceUri is the same as TargetUri");
    auto ret = CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid source uri");
    ret = CheckUriSupport(targetUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid targetUri uri");

    string destRelativePath;
    if (!GetAlbumRelativePathFromDB(targetUri, destRelativePath)) {
        MEDIA_ERR_LOG("Move target parent uri is not correct %{private}s", targetUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    if (!CheckDestRelativePath(destRelativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_URI, MEDIA_DATA_DB_FILE_PATH, MEDIA_DATA_DB_NAME,
        MEDIA_DATA_DB_MEDIA_TYPE, MEDIA_DATA_DB_RELATIVE_PATH };
    auto result = GetResultSetFromDb(MEDIA_DATA_DB_URI, sourceUri, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_MODIFY_DATA_FAIL, "Move source uri is not correct %{private}s",
        sourceUri.c_str());
    auto fileAsset = make_shared<FileAsset>();
    fileAsset->SetId(GetInt32Val(MEDIA_DATA_DB_ID, result));
    fileAsset->SetUri(GetStringVal(MEDIA_DATA_DB_URI, result));
    fileAsset->SetPath(GetStringVal(MEDIA_DATA_DB_FILE_PATH, result));
    fileAsset->SetDisplayName(GetStringVal(MEDIA_DATA_DB_NAME, result));
    fileAsset->SetMediaType(static_cast<MediaType>(GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result)));
    string relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
    fileAsset->SetRelativePath(GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result));
    result->Close();
    if (fileAsset->GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        if (!CheckRootDir(fileAsset, destRelativePath)) {
            MEDIA_ERR_LOG("Move file to another type album, denied");
            return E_DENIED_MOVE;
        }
        string bucketId = MediaFileUtils::GetIdFromUri(targetUri);
        ret = HandleAlbumMove(fileAsset, destRelativePath, bucketId);
    } else {
        ret = HandleFileMove(fileAsset, destRelativePath);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}

void TranslateCopyResult(CopyResult &copyResult)
{
    auto iter = mediaErrCodeMap.find(copyResult.errCode);
    if (iter != mediaErrCodeMap.end()) {
        copyResult.errCode = iter->second.first;
        if (copyResult.errMsg.empty()) {
            copyResult.errMsg = iter->second.second;
        }
    }
}

void GetUriByRelativePath(const string &relativePath, string &fileUriStr)
{
    string path = ROOT_MEDIA_DIR + relativePath;
    if (path.back() == '/') {
        path.pop_back();
    }

    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_MEDIA_TYPE };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_FILE_PATH, path, columns);
    CHECK_AND_RETURN_LOG(result != nullptr,
        "Get Uri failed, relativePath: %{private}s", relativePath.c_str());
    int64_t fileId = GetInt32Val(MEDIA_DATA_DB_ID, result);
#ifdef MEDIALIBRARY_COMPATIBILITY
    fileId = MediaFileUtils::GetVirtualIdByType(fileId, MediaType::MEDIA_TYPE_FILE);
    fileUriStr = MediaFileUri(MediaType::MEDIA_TYPE_FILE, to_string(fileId)).ToString();
#else
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
    fileUriStr = MediaFileUri(MediaType(mediaType), to_string(fileId)).ToString();
#endif
}

int GetRelativePathByUri(const string &uriStr, string &relativePath)
{
    vector<string> columns = { MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_NAME };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, uriStr, columns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_NO_SUCH_FILE,
        "Get uri failed, relativePath: %{private}s", relativePath.c_str());
    relativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
    relativePath += GetStringVal(MEDIA_DATA_DB_NAME, result) + SLASH_CHAR;
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(relativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    return E_SUCCESS;
}

int GetDuplicateDirectory(const string &srcUriStr, const string &destUriStr, Uri &uri)
{
    vector<string> srcColumns = { MEDIA_DATA_DB_NAME };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, srcUriStr, srcColumns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_NO_SUCH_FILE,
        "Get source uri failed, relativePath: %{private}s", srcUriStr.c_str());
    string srcDirName = GetStringVal(MEDIA_DATA_DB_NAME, result);

    string destRelativePath;
    vector<string> destColumns = { MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_NAME };
    result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, destUriStr, destColumns);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_NO_SUCH_FILE,
        "Get destination uri failed, relativePath: %{private}s", destUriStr.c_str());
    destRelativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(destRelativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    destRelativePath += GetStringVal(MEDIA_DATA_DB_NAME, result) + SLASH_CHAR;
    string existUriStr;
    GetUriByRelativePath(destRelativePath + srcDirName, existUriStr);
    uri = Uri { existUriStr };
    return E_SUCCESS;
}

int32_t InsertFileOperation(string &destRelativePath, string &srcUriStr)
{
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    valuesBucket.Put(MEDIA_DATA_DB_URI, srcUriStr);
    Uri copyUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR +
                    MEDIA_FILEOPRN_COPYASSET);
    MediaLibraryCommand cmd(copyUri);
    return MediaLibraryDataManager::GetInstance()->Insert(cmd, valuesBucket);
}

int CopyFileOperation(string &srcUriStr, string &destRelativePath, CopyResult &copyResult, bool force)
{
    vector<string> columns = { MEDIA_DATA_DB_RELATIVE_PATH, MEDIA_DATA_DB_NAME };
    auto result = MediaFileExtentionUtils::GetResultSetFromDb(MEDIA_DATA_DB_URI, srcUriStr, columns);
    if (result == nullptr) {
        MEDIA_ERR_LOG("Get Uri failed, relativePath: %{private}s", srcUriStr.c_str());
        copyResult.errCode = E_NO_SUCH_FILE;
        copyResult.errMsg = "";
        TranslateCopyResult(copyResult);
        return COPY_EXCEPTION;
    }
    string srcRelativePath = GetStringVal(MEDIA_DATA_DB_RELATIVE_PATH, result);
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(srcRelativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    string srcFileName = GetStringVal(MEDIA_DATA_DB_NAME, result);
    string existFile;
    GetUriByRelativePath(destRelativePath + srcFileName, existFile);
    if (!existFile.empty()) {
        if (force) {
            Uri existFileUri { existFile };
            MediaFileExtentionUtils::Delete(existFileUri);
        } else {
            copyResult.sourceUri = srcUriStr;
            copyResult.destUri = existFile;
            copyResult.errCode = E_FILE_EXIST;
            copyResult.errMsg = "";
            TranslateCopyResult(copyResult);
            return COPY_NOEXCEPTION;
        }
    }
#ifdef MEDIALIBRARY_COMPATIBILITY
    if (!CheckDestRelativePath(destRelativePath)) {
        return JS_ERR_PERMISSION_DENIED;
    }
#endif
    int fileId = InsertFileOperation(destRelativePath, srcUriStr);
    if (fileId < 0) {
        MEDIA_ERR_LOG("Insert media library error, fileId: %{public}d", fileId);
        copyResult.sourceUri = srcUriStr;
        copyResult.errCode = fileId;
        copyResult.errMsg = "Insert media library fail";
        TranslateCopyResult(copyResult);
        return COPY_NOEXCEPTION;
    }
    return E_SUCCESS;
}

int CopyDirectoryOperation(FileInfo &fileInfo, Uri &destUri, vector<CopyResult> &copyResult, bool force)
{
    vector<FileInfo> fileInfoVec;
    FileAccessFwk::FileFilter filter { {}, {}, {}, -1, -1, false, false };
    int64_t offset = 0;
    int copyRet = E_SUCCESS;
    int ret = E_SUCCESS;
    string prevDestUriStr;
    string destRelativePath;
    do {
        fileInfoVec.clear();
        ret = MediaFileExtentionUtils::ListFile(fileInfo, offset, MAX_COUNT, filter, fileInfoVec);
        if (ret != E_SUCCESS) {
            MEDIA_ERR_LOG("ListFile get result error, code:%{public}d", ret);
            CopyResult result { "", "", ret, "" };
            copyResult.clear();
            copyResult.push_back(result);
            return COPY_EXCEPTION;
        }

        for (auto info : fileInfoVec) {
            if (info.mode & DOCUMENT_FLAG_REPRESENTS_DIR) {
                Uri dUri { "" };
                ret = MediaFileExtentionUtils::Mkdir(destUri, info.fileName, dUri);
                if (ret == E_FILE_EXIST) {
                    GetDuplicateDirectory(info.uri, destUri.ToString(), dUri);
                } else if (ret < 0) {
                    MEDIA_ERR_LOG("Mkdir get result error, code:%{public}d", ret);
                    CopyResult result { "", "", ret, "" };
                    copyResult.clear();
                    copyResult.push_back(result);
                    return COPY_EXCEPTION;
                }
                ret = CopyDirectoryOperation(info, dUri, copyResult, force);
                if (ret == COPY_EXCEPTION) {
                    MEDIA_ERR_LOG("Recursive directory copy error");
                    return ret;
                }
                if (ret == COPY_NOEXCEPTION) {
                    copyRet = ret;
                }
            } else if (info.mode & DOCUMENT_FLAG_REPRESENTS_FILE) {
                CopyResult result;
                string destUriStr = destUri.ToString();
                if (destUriStr != prevDestUriStr) {
                    ret = GetRelativePathByUri(destUriStr, destRelativePath);
                    if (ret != E_SUCCESS) {
                        MEDIA_ERR_LOG("Get relative Path error");
                        result.errCode = ret;
                        TranslateCopyResult(result);
                        copyResult.clear();
                        copyResult.push_back(result);
                        return ret;
                    }
                    prevDestUriStr = destUriStr;
                }
                ret = CopyFileOperation(info.uri, destRelativePath, result, force);
                if (ret == COPY_EXCEPTION) {
                    MEDIA_ERR_LOG("Copy file exception");
                    copyResult.clear();
                    copyResult.push_back(result);
                    return ret;
                }
                if (ret == COPY_NOEXCEPTION) {
                    copyResult.push_back(result);
                    copyRet = ret;
                }
            }
        }
        offset += MAX_COUNT;
    } while (fileInfoVec.size() == MAX_COUNT);
    return copyRet;
}

int32_t MediaFileExtentionUtils::Copy(const Uri &sourceUri, const Uri &destUri, vector<CopyResult> &copyResult,
    bool force)
{
    FileAccessFwk::FileInfo fileInfo;
    int ret = GetFileInfoFromUri(sourceUri, fileInfo);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("get FileInfo from uri error, code:%{public}d", ret);
        CopyResult result { "", "", ret, "" };
        TranslateCopyResult(result);
        copyResult.clear();
        copyResult.push_back(result);
        return COPY_EXCEPTION;
    }

    string srcUriStr = sourceUri.ToString();
    string destUriStr = destUri.ToString();
    Uri newDestUri { "" };
    if (fileInfo.mode & DOCUMENT_FLAG_REPRESENTS_DIR) {
        ret = Mkdir(destUri, fileInfo.fileName, newDestUri);
        if (ret == E_FILE_EXIST) {
            GetDuplicateDirectory(srcUriStr, destUriStr, newDestUri);
        } else if (ret < 0) {
            CopyResult result { "", "", ret, "" };
            TranslateCopyResult(result);
            copyResult.clear();
            copyResult.push_back(result);
            return COPY_EXCEPTION;
        }
        ret = CopyDirectoryOperation(fileInfo, newDestUri, copyResult, force);
    } else if (fileInfo.mode & DOCUMENT_FLAG_REPRESENTS_FILE) {
        CopyResult result;
        string destRelativePath;
        ret = GetRelativePathByUri(destUriStr, destRelativePath);
        if (ret != E_SUCCESS) {
            MEDIA_ERR_LOG("Get relative Path error");
            result.errCode = ret;
            TranslateCopyResult(result);
            copyResult.clear();
            copyResult.push_back(result);
            return ret;
        }
        ret = CopyFileOperation(srcUriStr, destRelativePath, result, force);
        if (ret != E_SUCCESS) {
            copyResult.push_back(result);
        }
    }
    return ret;
}
} // Media
} // OHOS
