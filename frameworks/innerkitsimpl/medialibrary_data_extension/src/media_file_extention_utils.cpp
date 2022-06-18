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

#include "media_file_extention_utils.h"
#include "media_lib_service_const.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "media_file_utils.h"
#include "uri_helper.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
string MediaFileExtentionUtils::GetFileMediaTypeUri(MediaType mediaType, const string& networkId)
{
    string uri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    switch (mediaType) {
        case MEDIA_TYPE_AUDIO:
            return uri + MEDIALIBRARY_TYPE_AUDIO_URI;
        case MEDIA_TYPE_VIDEO:
            return uri + MEDIALIBRARY_TYPE_VIDEO_URI;
        case MEDIA_TYPE_IMAGE:
            return uri + MEDIALIBRARY_TYPE_IMAGE_URI;
        case MEDIA_TYPE_FILE:
        default:
            return uri + MEDIALIBRARY_TYPE_FILE_URI;
    }
}

void GetSingleFileInfo(FileAccessFwk::FileInfo &fileInfo, shared_ptr<AbsSharedResultSet> &result)
{
    int32_t index = 0;
    int fileId;
    int mediaType;
    string fileName;
    int64_t fileSize, date_modified;
    result->GetColumnIndex(MEDIA_DATA_DB_ID, index);
    result->GetInt(index, fileId);
    result->GetColumnIndex(MEDIA_DATA_DB_NAME, index);
    result->GetString(index, fileName);
    result->GetColumnIndex(MEDIA_DATA_DB_MEDIA_TYPE, index);
    result->GetInt(index, mediaType);
    result->GetColumnIndex(MEDIA_DATA_DB_SIZE, index);
    result->GetLong(index, fileSize);
    result->GetColumnIndex(MEDIA_DATA_DB_DATE_MODIFIED, index);
    result->GetLong(index, date_modified);
    string networkId;
    string uri = MediaFileExtentionUtils::GetFileMediaTypeUri(MediaType(mediaType), networkId) +
         '/' + to_string(fileId);
    fileInfo.uri = Uri(uri);
    fileInfo.fileName = fileName;
    fileInfo.mimiType = mediaType;
    fileInfo.size = fileSize;
    fileInfo.mtime = date_modified;
    if (mediaType == MEDIA_TYPE_ALBUM) {
        fileInfo.mode = MEDIALIBRARY_FOLDER;
    }
}

void GetFileInfoFromResult(shared_ptr<AbsSharedResultSet> &result, vector<FileAccessFwk::FileInfo> &fileList)
{
    int count = 0;
    result->GetRowCount(count);
    MEDIA_DEBUG_LOG("count %{public}d", count);
    if (count == 0) {
        MEDIA_ERR_LOG("DataShareResultSet null");
        return;
    }
    result->GoToFirstRow();
    for (int i = 0; i < count; i++) {
        FileAccessFwk::FileInfo fileInfo;
        GetSingleFileInfo(fileInfo, result);
        MEDIA_DEBUG_LOG("fileInfo.uri %{public}s", fileInfo.uri.ToString().c_str());
        fileList.push_back(fileInfo);
        result->GoToNextRow();
    }
}

std::shared_ptr<AbsSharedResultSet> GetListFileResult(const string &queryUri,
                                                      const string &selection,
                                                      vector<string> &selectionArgs)
{
    Uri uri(queryUri);
    DataSharePredicates predicates;
    predicates.SetWhereClause(selection);
    predicates.SetWhereArgs(selectionArgs);
    vector<string> columns;
    auto resultSet = MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    return resultSet;
}

bool GetAlbumRelativePath(const string &selectUri, const string &networkId, string &relativePath)
{
    string queryUri = MEDIALIBRARY_DATA_URI + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId +
            MEDIALIBRARY_DATA_URI_IDENTIFIER + "/" + MEDIA_ALBUMOPRN_QUERYALBUM;
    }
    string selection = MEDIA_DATA_DB_ID + " LIKE ? ";
    string id = MediaLibraryDataManagerUtils::GetIdFromUri(selectUri);
    vector<string> selectionArgs = { id };
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    Uri uri(queryUri);
    shared_ptr<AbsSharedResultSet> result =
        MediaLibraryDataManager::GetInstance()->QueryRdb(uri, columns, predicates);
    int count = 0;
    result->GetRowCount(count);
    if (count == 0) {
        MEDIA_ERR_LOG("GetAlbum fail");
        return false;
    }
    result->GoToFirstRow();
    int columnIndex = 0;
    result->GetColumnIndex(MEDIA_DATA_DB_RELATIVE_PATH, columnIndex);
    result->GetString(columnIndex, relativePath);
    MEDIA_DEBUG_LOG("relativePath %{public}s", relativePath.c_str());
    return true;
}

vector<FileAccessFwk::FileInfo> MediaFileExtentionUtils::ListFile(string selectUri)
{
    MEDIA_DEBUG_LOG("selectUri %{public}s", selectUri.c_str());
    UriHelper::ListFileType listFileType = UriHelper::ResolveUri(selectUri);
    MEDIA_DEBUG_LOG("listFileType %{public}d", listFileType);
    string relativePath;
    vector<FileAccessFwk::FileInfo> fileList;
    string networkId = MediaLibraryDataManagerUtils::GetNetworkIdFromUri(selectUri);
    if (listFileType == UriHelper::LISTFILE_ROOT) {
        relativePath = "";
    } else if (listFileType == UriHelper::LISTFILE_DIR) {
        if (!GetAlbumRelativePath(selectUri, networkId, relativePath)) {
            MEDIA_ERR_LOG("selectUri is not valid album uri");
            return fileList;
        }
    }
    MEDIA_DEBUG_LOG("relativePath %{public}s", relativePath.c_str());
    string selection = MEDIA_DATA_DB_RELATIVE_PATH + " LIKE ?";
    vector<string> selectionArgs = { relativePath };
    string queryUri;
    if (!networkId.empty()) {
        queryUri = MEDIALIBRARY_DATA_ABILITY_PREFIX + networkId + MEDIALIBRARY_DATA_URI_IDENTIFIER;
    } else {
        queryUri = MEDIALIBRARY_DATA_URI;
    }
    MEDIA_DEBUG_LOG("queryUri %{public}s", queryUri.c_str());
    std::shared_ptr<AbsSharedResultSet> resultSet = GetListFileResult(queryUri, selection, selectionArgs);
    GetFileInfoFromResult(resultSet, fileList);
    MEDIA_DEBUG_LOG("fileList.size() count %{public}lu", fileList.size());
    return fileList;
}
} // Media
} // OHOS