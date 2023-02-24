/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include "media_file_utils.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_errno.h"
#include "medialibrary_object_utils.h"
#include "medialibrary_type_const.h"
#include "medialibrary_smartalbum_map_db.h"
#include "result_set_utils.h"
#include "scanner_utils.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::FileAccessFwk;

namespace OHOS {
namespace Media {
constexpr int32_t ALBUM_MODE_RW =
    DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
constexpr int32_t FILE_MODE_RW =
    DOCUMENT_FLAG_REPRESENTS_FILE | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;

int MediaFileExtentionUtils::OpenFile(const Uri &uri, const int flags, int &fd)
{
    fd = -1;
    if (!MediaFileExtentionUtils::CheckUriValid(uri.ToString())) {
        return E_URI_INVALID;
    }
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri.ToString());
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
        MEDIA_ERR_LOG("invalid OpenFile flags %{private}d", flags);
        return E_OPENFILE_INVALID_FLAG;
    }
    auto ret = MediaLibraryDataManager::GetInstance()->OpenFile(uri, mode);
    if (ret < 0) {
        return ret;
    } else {
        fd = ret;
        return E_SUCCESS;
    }
}

int MediaFileExtentionUtils::CreateFile(const Uri &parentUri, const string &displayName,  Uri &newFileUri)
{
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid file displayName %{private}s", displayName.c_str());
        return E_INVAVLID_DISPLAY_NAME;
    }
    string parentUriStr = parentUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    Uri createFileUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_CREATEASSET);
    string albumId = MediaLibraryDataManagerUtils::GetIdFromUri(parentUriStr);
    string albumPath = MediaLibraryObjectUtils::GetPathByIdFromDb(albumId);
    string relativePath = albumPath.substr(ROOT_MEDIA_DIR.size()) + SLASH_CHAR;
    string destPath = albumPath + SLASH_CHAR + displayName;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, MediaFileUtils::GetMediaType(displayName));
    ret = MediaLibraryDataManager::GetInstance()->Insert(createFileUri, valuesBucket);
    if (ret > 0) {
        newFileUri = Uri(MediaFileUtils::GetUriByNameAndId(displayName, "", ret));
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("CreateFile insert fail, %{public}d", ret);
        return ret;
    }
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
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::GetAlbumRelativePathFromDB(parentUriStr, "", relativePath),
            E_URI_IS_NOT_ALBUM, "selectUri is not valid album uri %{private}s", parentUriStr.c_str());
    }
    Uri mkdirUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR + MEDIA_DIROPRN_FMS_CREATEDIR);
    string dirPath = ROOT_MEDIA_DIR + relativePath + displayName;
    if (MediaLibraryObjectUtils::IsFileExistInDb(dirPath)) {
        MEDIA_ERR_LOG("Create dir is existed %{private}s", dirPath.c_str());
        return E_FILE_EXIST;
    }
    relativePath = relativePath + displayName + SLASH_CHAR;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    ret = MediaLibraryDataManager::GetInstance()->Insert(mkdirUri, valuesBucket);
    if (ret > 0) {
        int32_t dirId = MediaLibraryObjectUtils::GetParentIdByIdFromDb(to_string(ret));
        newFileUri = Uri(MediaFileUtils::GetUriByNameAndId(displayName, "", dirId));
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("mkdir insert fail, %{public}d", ret);
        return ret;
    }
}

int MediaFileExtentionUtils::Delete(const Uri &sourceFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    auto result = MediaFileExtentionUtils::GetFileFromDB(sourceUri, "");
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "GetFileFromDB result set is nullptr");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, E_FAIL, "AbsSharedResultSet empty");
    ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, E_FAIL, "Failed to shift at first row");
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(sourceUri);
    int fileId = stoi(id);
    int errCode = 0;
    DataShareValuesBucket valuesBucket;
    if (mediaType == MEDIA_TYPE_ALBUM) {
        valuesBucket.Put(MEDIA_DATA_DB_ID, fileId);
        Uri trashAlbumUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DIROPRN + SLASH_CHAR +
            MEDIA_DIROPRN_FMS_TRASHDIR);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAlbumUri, valuesBucket);
    } else {
        valuesBucket.Put(SMARTALBUMMAP_DB_ALBUM_ID, TRASH_ALBUM_ID_VALUES);
        valuesBucket.Put(SMARTALBUMMAP_DB_CHILD_ASSET_ID, fileId);
        Uri trashAssetUri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_SMARTALBUMMAPOPRN + SLASH_CHAR +
            MEDIA_SMARTALBUMMAPOPRN_ADDSMARTALBUM);
        errCode = MediaLibraryDataManager::GetInstance()->Insert(trashAssetUri, valuesBucket);
    }
    return errCode;
}

bool MediaFileExtentionUtils::CheckUriValid(const string &uri)
{
    size_t pos = uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX);
    if (pos == string::npos) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
    size_t slashIndex = uri.rfind(SLASH_CHAR);
    if (slashIndex == string::npos) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
    string id = uri.substr(slashIndex + 1);
    if (id.empty()) {
        MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
        return false;
    }
    for (const char &c : id) {
        if (!isdigit(c)) {
            MEDIA_ERR_LOG("invalid uri %{private}s", uri.c_str());
            return false;
        }
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

/**
 * URI_ROOT Return four uri of media type(images, audios, videos and file).
 *  datashare:///media/root
 * URI_MEDIA_ROOT Return all albums of the specified type.
 *  datashare:///media/root/image|audio|video
 * URI_FILE_ROOT Return the files and folders under the root directory.
 *  datashare:///media/root/file
 * URI_DIR Return the files and folders in the directory.
 *  datashare:///media/file/1
 * URI_ALBUM Return the specified media type assets in the Album.
 *  datashare:///media/file/1
 */
int32_t MediaFileExtentionUtils::ResolveUri(const FileInfo &fileInfo, MediaFileUriType &uriType)
{
    string uri = fileInfo.uri;
    if (uri.find(MEDIALIBRARY_DATA_ABILITY_PREFIX) != 0) {
        return E_INVALID_URI;
    }
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    uri = uri.substr(MEDIALIBRARY_DATA_ABILITY_PREFIX.length() + networkId.length());
    if (uri.find(MEDIALIBRARY_DATA_URI_IDENTIFIER) != 0) {
        return E_INVALID_URI;
    }
    uri = uri.substr(MEDIALIBRARY_DATA_URI_IDENTIFIER.length());
    if (uri == MEDIALIBRARY_ROOT) {
        uriType = MediaFileUriType::URI_ROOT;
        return E_SUCCESS;
    }
    if (uri.find(MEDIALIBRARY_ROOT) == 0) {
        return ResolveRootUri(uri, uriType);
    }
    if (uri.find(MEDIALIBRARY_TYPE_FILE_URI) == 0) {
        return ResolveUriWithType(fileInfo.mimeType, uriType);
    }
    return E_INVALID_URI;
}

bool MediaFileExtentionUtils::CheckValidDirName(const std::string &displayName)
{
    AbsRdbPredicates absPredicates(MEDIATYPE_DIRECTORY_TABLE);
    absPredicates.EqualTo(CATEGORY_MEDIATYPE_DIRECTORY_DB_DIRECTORY, displayName);
    vector<string> columns;
    auto queryResultSet = MediaLibraryDataManager::GetInstance()->rdbStore_->Query(absPredicates, columns);
    CHECK_AND_RETURN_RET_LOG(queryResultSet != nullptr, false, "Query functionality failed");
    int32_t count = 0;
    queryResultSet->GetRowCount(count);
    return count > 0;
}

int32_t MediaFileExtentionUtils::CheckMkdirValid(MediaFileUriType uriType, const string &parentUriStr,
    const string &displayName)
{
    if (uriType == MediaFileUriType::URI_FILE_ROOT) {
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckDistributedUri(parentUriStr),
            E_DISTIBUTED_URI_NO_SUPPORT, "Mkdir not support distributed operation");
        CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckValidDirName(displayName + SLASH_CHAR),
            E_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    } else {
        auto ret = MediaFileExtentionUtils::CheckUriSupport(parentUriStr);
        CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
        CHECK_AND_RETURN_RET_LOG(MediaFileUtils::CheckDisplayName(displayName),
            E_INVAVLID_DISPLAY_NAME, "invalid directory displayName %{private}s", displayName.c_str());
    }
    return E_SUCCESS;
}

shared_ptr<AbsSharedResultSet> MediaFileExtentionUtils::GetFileFromDB(const string &selectUri, const string &networkId)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    }
    string selection = MEDIA_DATA_DB_ID + " = ? ";
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(selectUri);
    vector<string> selectionArgs = { id };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

bool MediaFileExtentionUtils::GetAlbumRelativePathFromDB(const string &selectUri, const string &networkId,
    string &relativePath)
{
    auto result = MediaFileExtentionUtils::GetFileFromDB(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "Failed to shift at first row");
    int mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, result, TYPE_INT32));
    CHECK_AND_RETURN_RET_LOG(mediaType == MEDIA_TYPE_ALBUM, false, "selectUri is not album");
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    string displayname = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME, result, TYPE_STRING));
    relativePath = relativePath + displayname + SLASH_CHAR;
    return true;
}

string GetQueryUri(const FileInfo &parentInfo, MediaFileUriType uriType)
{
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
    string queryUri;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    } else {
        queryUri = MEDIALIBRARY_DATA_URI;
    }
    if (uriType == URI_MEDIA_ROOT) {
        queryUri += SLASH_CHAR + MEDIA_ALBUMOPRN_QUERYALBUM;
    }
    return queryUri;
}

void ChangeToLowerCase(vector<string> &vec)
{
    for (auto &s : vec) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
    }
}

int32_t GetListFilePredicates(const FileInfo &parentInfo, const DistributedFS::FileFilter &filter, string &selection,
    vector<string> &selectionArgs)
{
    string selectUri = parentInfo.uri;
    if (!MediaFileExtentionUtils::CheckUriValid(selectUri)) {
        MEDIA_ERR_LOG("selectUri is not valid uri %{private}s", selectUri.c_str());
        return E_URI_INVALID;
    }
    string relativePath;
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
    if (!MediaFileExtentionUtils::GetAlbumRelativePathFromDB(selectUri, networkId, relativePath)) {
        MEDIA_ERR_LOG("selectUri is not valid album uri %{private}s", selectUri.c_str());
        return E_URI_IS_NOT_ALBUM;
    }
    selection = MEDIA_DATA_DB_RELATIVE_PATH + " = ? AND " + MEDIA_DATA_DB_IS_TRASH + " = ? ";
    selectionArgs = { relativePath, to_string(NOT_ISTRASH) };
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
    FileInfo fileInfo;
    fileInfo.mode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ;
    string selectUri = parentInfo.uri;
    fileInfo.fileName = "MEDIA_TYPE_FILE";
    fileInfo.uri = selectUri + MEDIALIBRARY_TYPE_FILE_URI;
    fileInfo.mimeType = DEFAULT_FILE_MIME_TYPE;
    fileList.push_back(fileInfo);
    fileInfo.fileName = "MEDIA_TYPE_IMAGE";
    fileInfo.uri = selectUri + MEDIALIBRARY_TYPE_IMAGE_URI;
    fileInfo.mimeType = DEFAULT_IMAGE_MIME_TYPE;
    fileList.push_back(fileInfo);
    fileInfo.fileName = "MEDIA_TYPE_VIDEO";
    fileInfo.uri = selectUri + MEDIALIBRARY_TYPE_VIDEO_URI;
    fileInfo.mimeType = DEFAULT_VIDEO_MIME_TYPE;
    fileList.push_back(fileInfo);
    fileInfo.fileName = "MEDIA_TYPE_AUDIO";
    fileInfo.uri = selectUri + MEDIALIBRARY_TYPE_AUDIO_URI;
    fileInfo.mimeType = DEFAULT_AUDIO_MIME_TYPE;
    fileList.push_back(fileInfo);
    return E_SUCCESS;
}

std::shared_ptr<AbsSharedResultSet> GetResult(const Uri &uri, MediaFileUriType uriType, const string &selection,
    const vector<string> &selectionArgs)
{
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    vector<string> columns = { MEDIA_DATA_DB_ID, MEDIA_DATA_DB_SIZE, MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_MIME_TYPE, MEDIA_DATA_DB_NAME, MEDIA_DATA_DB_MEDIA_TYPE };
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
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

std::shared_ptr<AbsSharedResultSet> GetMediaRootResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount)
{
    Uri uri(GetQueryUri(parentInfo, uriType));
    DataSharePredicates predicates;
    predicates.EqualTo(MEDIA_DATA_DB_MEDIA_TYPE, MimeType2MediaType(parentInfo.mimeType));
    predicates.EqualTo(MEDIA_DATA_DB_IS_TRASH, to_string(NOT_ISTRASH));
    predicates.Limit(maxCount, offset);
    vector<string> columns = { MEDIA_DATA_DB_BUCKET_ID, MEDIA_DATA_DB_TITLE, MEDIA_DATA_DB_DATE_MODIFIED };
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

std::shared_ptr<AbsSharedResultSet> GetListRootResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount)
{
    string selection = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? AND " +
        MEDIA_DATA_DB_IS_TRASH + " = ? LIMIT ?, ?";
    vector<string> selectionArgs = { to_string(ROOT_PARENT_ID), to_string(MEDIA_TYPE_NOFILE), to_string(NOT_ISTRASH),
        to_string(offset), to_string(maxCount) };
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
}

std::shared_ptr<AbsSharedResultSet> GetListDirResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const DistributedFS::FileFilter &filter)
{
    string selection;
    vector<string> selectionArgs;
    int32_t ret = GetListFilePredicates(parentInfo, filter, selection, selectionArgs);
    if (ret != E_SUCCESS) {
        return nullptr;
    }
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? LIMIT ?, ?";
    selectionArgs.push_back(to_string(MEDIA_TYPE_NOFILE));
    selectionArgs.push_back(to_string(offset));
    selectionArgs.push_back(to_string(maxCount));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
}

std::shared_ptr<AbsSharedResultSet> GetListAlbumResult(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const DistributedFS::FileFilter &filter)
{
    string selection;
    vector<string> selectionArgs;
    int32_t ret = GetListFilePredicates(parentInfo, filter, selection, selectionArgs);
    if (ret != E_SUCCESS) {
        return nullptr;
    }
    selection += " AND " + MEDIA_DATA_DB_MEDIA_TYPE + " = ? LIMIT ?, ?";
    selectionArgs.push_back(MimeType2MediaType(parentInfo.mimeType));
    selectionArgs.push_back(to_string(offset));
    selectionArgs.push_back(to_string(maxCount));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetResult(uri, uriType, selection, selectionArgs);
}

int GetFileInfo(FileInfo &fileInfo, const shared_ptr<NativeRdb::ResultSet> &result, const string &networkId = "")
{
    int fileId = GetInt32Val(MEDIA_DATA_DB_ID, result);
    int mediaType = GetInt32Val(MEDIA_DATA_DB_MEDIA_TYPE, result);
    fileInfo.uri =
        MediaFileUtils::GetFileMediaTypeUri(MediaType(mediaType), networkId) + SLASH_CHAR + to_string(fileId);
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

int32_t GetAlbumInfoFromResult(const FileInfo &parentInfo, shared_ptr<AbsSharedResultSet> &result,
    vector<FileInfo> &fileList)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "AbsSharedResultSet is nullptr");
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
    FileInfo fileInfo;
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int fileId = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_BUCKET_ID, result, TYPE_INT32));
        fileInfo.fileName = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_TITLE, result, TYPE_STRING));
        fileInfo.mimeType = parentInfo.mimeType;
        fileInfo.uri =
            MediaFileUtils::GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId) + SLASH_CHAR + to_string(fileId);
        fileInfo.mtime =
            get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED, result, TYPE_INT64));
        fileInfo.mode = DOCUMENT_FLAG_REPRESENTS_DIR | DOCUMENT_FLAG_SUPPORTS_READ | DOCUMENT_FLAG_SUPPORTS_WRITE;
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}

int32_t GetFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<AbsSharedResultSet> &result,
    vector<FileInfo> &fileList)
{
    CHECK_AND_RETURN_RET_LOG(result != nullptr, E_FAIL, "AbsSharedResultSet is nullptr");
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        GetFileInfo(fileInfo, result, networkId);
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}

int32_t MediaFileExtentionUtils::ListFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, vector<FileInfo> &fileList)
{
    MediaFileUriType uriType;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    MEDIA_DEBUG_LOG("ListFile:: uriType: %d", uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("ResolveUri::invalid input fileInfo");
        return ret;
    }
    std::shared_ptr<AbsSharedResultSet> resultSet = nullptr;
    switch (uriType) {
        case URI_ROOT:
            return RootListFile(parentInfo, fileList);
        case URI_MEDIA_ROOT:
            resultSet = GetMediaRootResult(parentInfo, uriType, offset, maxCount);
            return GetAlbumInfoFromResult(parentInfo, resultSet, fileList);
        case URI_FILE_ROOT:
            resultSet = GetListRootResult(parentInfo, uriType, offset, maxCount);
            return GetFileInfoFromResult(parentInfo, resultSet, fileList);
        case URI_DIR:
            resultSet = GetListDirResult(parentInfo, uriType, offset, maxCount, filter);
            return GetFileInfoFromResult(parentInfo, resultSet, fileList);
        case URI_ALBUM:
            resultSet = GetListAlbumResult(parentInfo, uriType, offset, maxCount, filter);
            return GetFileInfoFromResult(parentInfo, resultSet, fileList);
        default:
            return E_FAIL;
    }
}

int32_t GetScanFileFileInfoFromResult(const FileInfo &parentInfo, shared_ptr<AbsSharedResultSet> &result,
    vector<FileInfo> &fileList)
{
    if (result == nullptr) {
        return E_FAIL;
    }
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        FileInfo fileInfo;
        GetFileInfo(fileInfo, result, networkId);
        fileList.push_back(fileInfo);
    }
    return E_SUCCESS;
}

std::shared_ptr<AbsSharedResultSet> GetScanFileResult(const Uri &uri, MediaFileUriType uriType, const string &selection,
    const vector<string> &selectionArgs)
{
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    vector<string> columns {
        MEDIA_DATA_DB_BUCKET_ID,
        MEDIA_DATA_DB_TITLE,
        MEDIA_DATA_DB_ID,
        MEDIA_DATA_DB_SIZE,
        MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_MIME_TYPE,
        MEDIA_DATA_DB_NAME,
        MEDIA_DATA_DB_MEDIA_TYPE
    };
    return MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

std::shared_ptr<AbsSharedResultSet> SetScanFileSelection(const FileInfo &parentInfo, MediaFileUriType uriType,
    const int64_t offset, const int64_t maxCount, const DistributedFS::FileFilter &filter)
{
    string filePath;
    vector<string> selectionArgs;
    if (uriType == MediaFileUriType::URI_ROOT) {
        filePath = ROOT_MEDIA_DIR;
        selectionArgs.push_back(filePath + "%");
    } else {
        string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(parentInfo.uri);
        auto result = MediaFileExtentionUtils::GetFileFromDB(parentInfo.uri, networkId);
        CHECK_AND_RETURN_RET_LOG(result != nullptr, nullptr, "GetFileFromDB Get fail");
        int count = 0;
        result->GetRowCount(count);
        CHECK_AND_RETURN_RET_LOG(count > 0, nullptr, "AbsSharedResultSet empty");
        auto ret = result->GoToFirstRow();
        CHECK_AND_RETURN_RET_LOG(ret == 0, nullptr, "Failed to shift at first row");
        filePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH, result, TYPE_STRING));
        selectionArgs.push_back(filePath + "/%");
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
    selection += " AND " + MEDIA_DATA_DB_IS_TRASH + " = ? LIMIT ?, ?";
    selectionArgs.push_back(to_string(NOT_ISTRASH));
    selectionArgs.push_back(to_string(offset));
    selectionArgs.push_back(to_string(maxCount));
    Uri uri(GetQueryUri(parentInfo, uriType));
    return GetScanFileResult(uri, uriType, selection, selectionArgs);
}

int32_t MediaFileExtentionUtils::ScanFile(const FileInfo &parentInfo, const int64_t offset, const int64_t maxCount,
    const DistributedFS::FileFilter &filter, vector<FileInfo> &fileList)
{
    MediaFileUriType uriType;
    auto ret = MediaFileExtentionUtils::ResolveUri(parentInfo, uriType);
    MEDIA_DEBUG_LOG("ScanFile:: uriType: %d", uriType);
    if (ret != E_SUCCESS) {
        MEDIA_ERR_LOG("ResolveUri::invalid input fileInfo");
        return ret;
    }
    std::shared_ptr<AbsSharedResultSet> resultSet = SetScanFileSelection(parentInfo, uriType, offset, maxCount,
        filter);
    return GetScanFileFileInfoFromResult(parentInfo, resultSet, fileList);
}

bool GetRootInfo(shared_ptr<AbsSharedResultSet> &result, RootInfo &rootInfo)
{
    string networkId = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NETWORK_ID, result, TYPE_STRING));
    rootInfo.uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER + MEDIALIBRARY_ROOT;
    rootInfo.displayName = get<string>(ResultSetUtils::GetValFromColumn(DEVICE_DB_NAME, result, TYPE_STRING));
    rootInfo.deviceFlags = DEVICE_FLAG_SUPPORTS_READ;
    rootInfo.deviceType = DEVICE_SHARED_TERMINAL;
    return true;
}

void GetRootInfoFromResult(shared_ptr<AbsSharedResultSet> &result, vector<RootInfo> &rootList)
{
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_LOG(count > 0, "AbsSharedResultSet empty");
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

void GetActivePeer(shared_ptr<AbsSharedResultSet> &result)
{
    std::string strQueryCondition = DEVICE_DB_DATE_MODIFIED + " = 0";
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(strQueryCondition);
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + SLASH_CHAR + MEDIA_DEVICE_QUERYACTIVEDEVICE);
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

int32_t MediaFileExtentionUtils::GetRoots(vector<RootInfo> &rootList)
{
    RootInfo rootInfo;
    // add local root
    rootInfo.uri = MEDIALIBRARY_DATA_URI + MEDIALIBRARY_ROOT;
    rootInfo.displayName = MEDIALIBRARY_LOCAL_DEVICE_NAME;
    rootInfo.deviceFlags = DEVICE_FLAG_SUPPORTS_READ | DEVICE_FLAG_SUPPORTS_WRITE;
    rootInfo.deviceType = DEVICE_LOCAL_DISK;
    rootList.push_back(rootInfo);
    shared_ptr<AbsSharedResultSet> resultSet;
    GetActivePeer(resultSet);
    GetRootInfoFromResult(resultSet, rootList);
    return E_SUCCESS;
}

int MediaFileExtentionUtils::Access(const Uri &uri, bool &isExist)
{
    isExist = false;
    string sourceUri = uri.ToString();
    CHECK_AND_RETURN_RET_LOG(MediaFileExtentionUtils::CheckUriValid(sourceUri), E_URI_INVALID,
        "Access::invalid uri: %{public}s", sourceUri.c_str());
    shared_ptr<FileAsset> srcAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(sourceUri);
    if ((srcAsset == nullptr) || (srcAsset->GetIsTrash() != NOT_ISTRASH)) {
        MEDIA_ERR_LOG("Access::uri is not correct: %{public}s", sourceUri.c_str());
        return E_INVALID_URI;
    }
    isExist = true;
    return E_SUCCESS;
}

bool MediaFileExtentionUtils::CheckDistributedUri(const string &uri)
{
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(uri);
    if (!networkId.empty()) {
        MEDIA_ERR_LOG("not support distributed operation %{public}s", uri.c_str());
        return false;
    }
    return true;
}

static bool GetRelativePathFromDB(const string &selectUri, const string &networkId, string &relativePath)
{
    auto result = MediaFileExtentionUtils::GetFileFromDB(selectUri, networkId);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, false, "AbsSharedResultSet empty");
    auto ret = result->GoToFirstRow();
    CHECK_AND_RETURN_RET_LOG(ret == 0, false, "Failed to shift at first row");
    relativePath = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH, result, TYPE_STRING));
    return true;
}

int32_t HandleFileRename(const shared_ptr<FileAsset> &srcAsset, const string &displayName,
    const string &destRelativePath)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, srcAsset->GetMediaType());
    valuesBucket.Put(MEDIA_DATA_DB_URI, srcAsset->GetUri());
    valuesBucket.Put(MEDIA_DATA_DB_NAME, displayName);
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ MediaLibraryDataManagerUtils::GetIdFromUri(srcAsset->GetUri()) });
    auto ret = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileRename Update ret %{private}d", ret);
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
    std::string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET ";
    // Update data "old albumPath/%" -> "new albumPath/%"
    modifySql += MEDIA_DATA_DB_FILE_PATH + " = replace("
        + MEDIA_DATA_DB_FILE_PATH + ", '" + srcPath + "/' , '" + newAlbumPath + "/'), ";
    // Update relative_path "old album relativePath/%" -> "new album relativePath/%"
    modifySql += MEDIA_DATA_DB_RELATIVE_PATH + " = replace(" + MEDIA_DATA_DB_RELATIVE_PATH
        + ", '" + GetRelativePathFromPath(srcPath) + "/', '" + GetRelativePathFromPath(newAlbumPath) + "/'), ";
    // Update date_modified "old time" -> "new time"
    modifySql += MEDIA_DATA_DB_DATE_MODIFIED + " = " + to_string(date_modified);
    modifySql += " WHERE " + MEDIA_DATA_DB_FILE_PATH + " LIKE '" + srcPath + "/%'";
    MEDIA_DEBUG_LOG("UpdateSubFilesPath modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t UpdateSubFilesBucketName(const string &srcId, const string &displayName)
{
    // Update bucket_display_name "old album displayName" -> "new album displayName"
    string modifySql = "UPDATE " + MEDIALIBRARY_TABLE + " SET " + MEDIA_DATA_DB_BUCKET_NAME + " = '" + displayName;
    modifySql += "' WHERE " + MEDIA_DATA_DB_PARENT_ID + " = " + srcId + " AND " +
        MEDIA_DATA_DB_MEDIA_TYPE + " <> " + to_string(MEDIA_TYPE_ALBUM);
    MEDIA_DEBUG_LOG("UpdateSubFilesBucketName modifySql %{private}s", modifySql.c_str());
    return MediaLibraryDataManager::GetInstance()->rdbStore_->ExecuteSql(modifySql);
}

int32_t HandleAlbumRename(const shared_ptr<FileAsset> &srcAsset, const string &displayName)
{
    if (srcAsset->GetRelativePath().empty()) {
        MEDIA_ERR_LOG("Rename dir in root dir, denied");
        return E_DENIED_RENAME;
    }
    string srcPath = srcAsset->GetPath();
    size_t slashIndex = srcPath.rfind(SLASH_CHAR);
    string destPath = srcPath.substr(0, slashIndex) + SLASH_CHAR + displayName;
    if (MediaLibraryObjectUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Rename file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    bool succ = MediaFileUtils::RenameDir(srcPath, destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }
    // update parent info
    string parentPath = ROOT_MEDIA_DIR + srcAsset->GetRelativePath();
    parentPath.pop_back();
    MediaLibraryObjectUtils::UpdateDateModified(parentPath);

    // update album info
    string srcId = to_string(srcAsset->GetId());
    int32_t updateResult = UpdateRenamedAlbumInfo(srcId, displayName, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateRenamedAlbumInfo failed");

    // update child info
    updateResult = UpdateSubFilesPath(srcPath, destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    updateResult = UpdateSubFilesBucketName(srcId, displayName);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL,
        "UpdateSubFilesBucketName failed");
    return E_SUCCESS;
}

int32_t MediaFileExtentionUtils::Rename(const Uri &sourceFileUri, const std::string &displayName, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid uri");
    if (!MediaFileUtils::CheckDisplayName(displayName)) {
        MEDIA_ERR_LOG("invalid displayName %{private}s", displayName.c_str());
        return E_INVAVLID_DISPLAY_NAME;
    }
    shared_ptr<FileAsset> srcAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(sourceUri);
    if (srcAsset == nullptr) {
        MEDIA_ERR_LOG("Rename source uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetRelativePathFromDB(sourceUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Rename uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    if (srcAsset->GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        ret = HandleAlbumRename(srcAsset, displayName);
    } else {
        ret = HandleFileRename(srcAsset, displayName, destRelativePath);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}

int32_t HandleFileMove(const shared_ptr<FileAsset> &srcAsset, const string &destRelativePath)
{
    string uri = MEDIALIBRARY_DATA_URI;
    Uri updateAssetUri(uri + SLASH_CHAR + MEDIA_FILEOPRN + SLASH_CHAR + MEDIA_FILEOPRN_MODIFYASSET);
    DataShare::DataSharePredicates predicates;
    DataShare::DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, srcAsset->GetMediaType());
    valuesBucket.Put(MEDIA_DATA_DB_URI, srcAsset->GetUri());
    valuesBucket.Put(MEDIA_DATA_DB_NAME, srcAsset->GetDisplayName());
    valuesBucket.Put(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    predicates.SetWhereClause(MEDIA_DATA_DB_ID + " = ? ");
    predicates.SetWhereArgs({ MediaLibraryDataManagerUtils::GetIdFromUri(srcAsset->GetUri()) });
    auto ret = MediaLibraryDataManager::GetInstance()->Update(updateAssetUri, valuesBucket, predicates);
    if (ret > 0) {
        return E_SUCCESS;
    } else {
        MEDIA_ERR_LOG("HandleFileMove Update ret %{private}d", ret);
        return ret;
    }
}

int32_t UpdateMovedAlbumInfo(const shared_ptr<FileAsset> &srcAsset, const string &bucketId, const string &newAlbumPath,
    const string &destRelativePath)
{
    int64_t date_modified = MediaFileUtils::GetAlbumDateModified(newAlbumPath);
    AbsRdbPredicates absPredicates(MEDIALIBRARY_TABLE);
    absPredicates.EqualTo(MEDIA_DATA_DB_ID, to_string(srcAsset->GetId()));
    ValuesBucket valuesBucket;
    valuesBucket.PutLong(MEDIA_DATA_DB_DATE_MODIFIED, date_modified);
    valuesBucket.PutInt(MEDIA_DATA_DB_PARENT_ID, stoi(bucketId));
    valuesBucket.PutInt(MEDIA_DATA_DB_BUCKET_ID, stoi(bucketId));
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, newAlbumPath);
    valuesBucket.PutString(MEDIA_DATA_DB_RELATIVE_PATH, destRelativePath);
    int32_t count = 0;
    return MediaLibraryDataManager::GetInstance()->rdbStore_->Update(count, valuesBucket, absPredicates);
}

int32_t HandleAlbumMove(const shared_ptr<FileAsset> &srcAsset, const string &destRelativePath, const string &bucketId)
{
    string destPath = ROOT_MEDIA_DIR + destRelativePath + srcAsset->GetDisplayName();
    if (MediaLibraryObjectUtils::IsFileExistInDb(destPath)) {
        MEDIA_ERR_LOG("Move file is existed %{private}s", destPath.c_str());
        return E_FILE_EXIST;
    }
    bool succ = MediaFileUtils::RenameDir(srcAsset->GetPath(), destPath);
    if (!succ) {
        MEDIA_ERR_LOG("Failed RenameDir errno %{public}d", errno);
        return E_MODIFY_DATA_FAIL;
    }

    // update parent info
    string srcParentPath = ROOT_MEDIA_DIR + srcAsset->GetRelativePath();
    srcParentPath.pop_back();
    string tarParentPath = ROOT_MEDIA_DIR + destRelativePath;
    tarParentPath.pop_back();
    MediaLibraryObjectUtils::UpdateDateModified(srcParentPath);
    MediaLibraryObjectUtils::UpdateDateModified(tarParentPath);

    // update album info
    int32_t updateResult = UpdateMovedAlbumInfo(srcAsset, bucketId, destPath, destRelativePath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateMovedAlbumInfo failed");

    // update child info
    updateResult = UpdateSubFilesPath(srcAsset->GetPath(), destPath);
    CHECK_AND_RETURN_RET_LOG(updateResult == NativeRdb::E_OK, E_UPDATE_DB_FAIL, "UpdateSubFilesPath failed");
    return E_SUCCESS;
}

int32_t CheckFileExtension(const string &relativePath, const string &name, int32_t mediaType)
{
    std::unordered_map<std::string, DirAsset> dirQuerySetMap;
    MediaLibraryDataManager::GetInstance()->MakeDirQuerySetMap(dirQuerySetMap);
    MediaLibraryDirOperations dirOprn;
    ValuesBucket values;
    values.PutString(MEDIA_DATA_DB_NAME, name);
    values.PutString(MEDIA_DATA_DB_RELATIVE_PATH, relativePath);
    values.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, mediaType);
    return dirOprn.HandleDirOperations(MEDIA_DIROPRN_CHECKDIR_AND_EXTENSION,
        values, MediaLibraryDataManager::GetInstance()->rdbStore_, dirQuerySetMap);
}

void GetMoveSubFile(const string &srcPath, shared_ptr<AbsSharedResultSet> &result)
{
    string queryUri = MEDIALIBRARY_DATA_URI;
    string selection = MEDIA_DATA_DB_FILE_PATH + " LIKE ? ";
    vector<string> selectionArgs = { srcPath + SLASH_CHAR + "%" };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    Uri uri(queryUri);
    result = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
}

bool CheckSubFileExtension(const string &srcPath, const string &destRelPath)
{
    shared_ptr<AbsSharedResultSet> result;
    GetMoveSubFile(srcPath, result);
    CHECK_AND_RETURN_RET_LOG(result != nullptr, false, "GetSrcFileFromResult Get fail");
    int count = 0;
    result->GetRowCount(count);
    CHECK_AND_RETURN_RET_LOG(count > 0, true, "AbsSharedResultSet empty");
    while (result->GoToNextRow() == NativeRdb::E_OK) {
        int32_t mediaType = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE,
            result, TYPE_INT32));
        string path = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH,
            result, TYPE_STRING));
        string name = get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_NAME,
            result, TYPE_STRING));
        if (mediaType == MEDIA_TYPE_ALBUM) {
            continue;
        }
        if (CheckFileExtension(destRelPath, name, mediaType) != E_SUCCESS) {
            return false;
        }
    }
    return true;
}

bool CheckRootDir(const shared_ptr<FileAsset> &srcAsset, const string &destRelPath)
{
    string srcRelPath = srcAsset->GetRelativePath();
    if (srcAsset->GetRelativePath().empty()) {
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
        return CheckSubFileExtension(srcAsset->GetPath(), destRelPath);
    }
    return true;
}

int32_t MediaFileExtentionUtils::Move(const Uri &sourceFileUri, const Uri &targetParentUri, Uri &newFileUri)
{
    string sourceUri = sourceFileUri.ToString();
    string targetUri = targetParentUri.ToString();
    CHECK_AND_RETURN_RET_LOG(sourceUri != targetUri, E_TWO_URI_ARE_THE_SAME,
        "sourceUri is the same as TargetUri");
    auto ret = MediaFileExtentionUtils::CheckUriSupport(sourceUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid source uri");
    ret = MediaFileExtentionUtils::CheckUriSupport(targetUri);
    CHECK_AND_RETURN_RET_LOG(ret == E_SUCCESS, ret, "invalid targetUri uri");
    shared_ptr<FileAsset> srcAsset = MediaLibraryObjectUtils::GetFileAssetFromDb(sourceUri);
    if (srcAsset == nullptr) {
        MEDIA_ERR_LOG("Move source uri is not correct %{private}s", sourceUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    string destRelativePath;
    if (!GetAlbumRelativePathFromDB(targetUri, "", destRelativePath)) {
        MEDIA_ERR_LOG("Move target parent uri is not correct %{private}s", targetUri.c_str());
        return E_MODIFY_DATA_FAIL;
    }
    if (srcAsset->GetMediaType() == MediaType::MEDIA_TYPE_ALBUM) {
        if (!CheckRootDir(srcAsset, destRelativePath)) {
            MEDIA_ERR_LOG("Move file to another type alubm, denied");
            return E_DENIED_MOVE;
        }
        string bucketId = MediaLibraryDataManagerUtils::GetIdFromUri(targetUri);
        ret = HandleAlbumMove(srcAsset, destRelativePath, bucketId);
    } else {
        ret = HandleFileMove(srcAsset, destRelativePath);
    }
    if (ret == E_SUCCESS) {
        newFileUri = Uri(sourceUri);
    }
    return ret;
}
} // Media
} // OHOS
