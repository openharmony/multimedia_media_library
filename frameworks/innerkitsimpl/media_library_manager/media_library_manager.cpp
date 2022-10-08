/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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
#define MLOG_TAG "MediaLibraryManager"

#include "media_library_manager.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "result_set_utils.h"

using namespace std;
using namespace OHOS::NativeRdb;

namespace OHOS {
namespace Media {
shared_ptr<DataShare::DataShareHelper> MediaLibraryManager::sDataShareHelper_ = nullptr;

MediaLibraryManager *MediaLibraryManager::GetMediaLibraryManager()
{
    static MediaLibraryManager mediaLibMgr;
    return &mediaLibMgr;
}

void MediaLibraryManager::InitMediaLibraryManager(const sptr<IRemoteObject> &token)
{
    if (sDataShareHelper_ == nullptr) {
        sDataShareHelper_ = DataShare::DataShareHelper::Creator(token, MEDIALIBRARY_DATA_URI);
    }
}

static void AppendFetchOptionSelection(std::string &selection, const std::string &newCondition)
{
    if (!newCondition.empty()) {
        if (!selection.empty()) {
            selection = "(" + selection + ") AND " + newCondition;
        } else {
            selection = newCondition;
        }
    }
}

unique_ptr<FetchResult<FileAsset>> MediaLibraryManager::GetFileAssets(const MediaFetchOptions &fetchOps)
{
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = nullptr;
    vector<string> columns;
    DataShare::DataSharePredicates predicates;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(fetchOps);

    string newCondition = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    AppendFetchOptionSelection(fetchOptions.selections, newCondition);
    fetchOptions.selectionArgs.emplace_back(to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(fetchOptions.selections);
    predicates.SetWhereArgs(fetchOptions.selectionArgs);
    predicates.SetOrder(fetchOptions.order);

    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;

    if (sDataShareHelper_ == nullptr
        || ((resultSet = sDataShareHelper_->Query(uri, predicates, columns)) == nullptr)) {
        MEDIA_ERR_LOG("Resultset retrieval failure caused Query operation to fail");
    } else {
        // Create FetchResult object using the contents of resultSet
        fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
        if (fetchFileResult == nullptr) {
            MEDIA_ERR_LOG("No fetch file result found!");
        }
    }

    return fetchFileResult;
}

vector<unique_ptr<AlbumAsset>> MediaLibraryManager::GetAlbums(const MediaFetchOptions &fetchOps)
{
    vector<unique_ptr<AlbumAsset>> albums;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(fetchOps);
    DataSharePredicates predicates;

    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("Ability Helper is null");
        return albums;
    }

    AppendFetchOptionSelection(fetchOptions.selections, MEDIA_DATA_DB_MEDIA_TYPE + " = ? ");
    fetchOptions.selectionArgs.emplace_back(to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(fetchOptions.selections);
    predicates.SetWhereArgs(fetchOptions.selectionArgs);
    if (!fetchOptions.order.empty()) {
        predicates.SetOrder(fetchOptions.order);
    }

    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    auto resultSet = sDataShareHelper_->Query(
        uri, predicates, columns);
    if (resultSet != nullptr) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
            if (albumData != nullptr) {
                // Get album id index and value
                albumData->SetAlbumId(get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ID,
                    resultSet, TYPE_INT32)));

                // Get album name index and value
                albumData->SetAlbumName(get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_ALBUM_NAME,
                    resultSet, TYPE_STRING)));

                // Get album path index and value
                albumData->SetAlbumPath(get<string>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_FILE_PATH,
                    resultSet, TYPE_STRING)));

                // Get album relative path index and value
                albumData->SetAlbumRelativePath(get<string>(ResultSetUtils::GetValFromColumn(
                    MEDIA_DATA_DB_RELATIVE_PATH, resultSet, TYPE_STRING)));

                // Get album date modified index and value
                int64_t albumDateModified;
                int32_t index;
                resultSet->GetColumnIndex(MEDIA_DATA_DB_DATE_MODIFIED, index);
                resultSet->GetLong(index, albumDateModified);
                albumData->SetAlbumDateModified(albumDateModified);

                // Add to album array
                albums.push_back(move(albumData));
            }
        }
    }

    return albums;
}

string MediaLibraryManager::CreateAsset(const FileAsset &fileAssetObj)
{
    string createUri;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, fileAssetObj.GetPath());
    valuesBucket.Put(MEDIA_DATA_DB_MEDIA_TYPE, fileAssetObj.GetMediaType());

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);

        int32_t index = sDataShareHelper_->Insert(createAssetUri, valuesBucket);
        if (index < 0) {
            MEDIA_ERR_LOG("Failed to create the file");
        } else {
            MediaType mediaType = fileAssetObj.GetMediaType();
            if (mediaType == MEDIA_TYPE_AUDIO) {
                createUri = MEDIALIBRARY_AUDIO_URI;
            } else if (mediaType == MEDIA_TYPE_IMAGE) {
                createUri = MEDIALIBRARY_IMAGE_URI;
            } else if (mediaType == MEDIA_TYPE_VIDEO) {
                createUri = MEDIALIBRARY_VIDEO_URI;
            } else {
                createUri = MEDIALIBRARY_FILE_URI;
            }

            createUri += "/" + to_string(index);
        }
    }

    return createUri;
}

int32_t MediaLibraryManager::ModifyAsset(const string &uri, const FileAsset &fileAssetObj)
{
    int32_t retVal = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, fileAssetObj.GetPath());

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri updateAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);
        retVal = sDataShareHelper_->Update(updateAssetUri, {}, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to modify the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::DeleteAsset(const string &uri)
{
    int32_t retVal = E_FAIL;
    if (uri.find(MEDIALIBRARY_DATA_URI) == string::npos) {
        return retVal;
    }

    string fileId;
    size_t pos = uri.rfind('/');
    if (pos != string::npos) {
        fileId = uri.substr(pos + 1);
    } else {
        return retVal;
    }

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET + "/" + fileId);
        retVal = sDataShareHelper_->Delete(deleteAssetUri, {});
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to delete the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::OpenAsset(const string &uri, string &mode)
{
    int32_t retVal = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);
    valuesBucket.Put(MEDIA_FILEMODE, mode);

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri openAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_OPENASSET);

        retVal = sDataShareHelper_->Insert(openAssetUri, valuesBucket);
        if (retVal <= 0) {
            MEDIA_ERR_LOG("Failed to open the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::CloseAsset(const string &uri, const int32_t fd)
{
    int32_t retVal = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_URI, uri);

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);

        if (close(fd) == E_SUCCESS) {
            retVal = sDataShareHelper_->Insert(closeAssetUri, valuesBucket);
        }

        if (retVal == E_FAIL) {
            MEDIA_ERR_LOG("Failed to close the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::CreateAlbum(const AlbumAsset &albumNapiObj)
{
    int32_t albumId = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_FILE_PATH, albumNapiObj.GetAlbumPath());

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);

        albumId = sDataShareHelper_->Insert(createAlbumUri, valuesBucket);
        if (albumId < 0) {
            MEDIA_ERR_LOG("Failed to create the album");
        }
    }

    return albumId;
}

int32_t MediaLibraryManager::ModifyAlbum(const int32_t albumId, const AlbumAsset &albumNapiObj)
{
    int32_t retVal = E_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.Put(MEDIA_DATA_DB_ID, albumId);
    valuesBucket.Put(MEDIA_DATA_DB_ALBUM_NAME, albumNapiObj.GetAlbumName());

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri modifyAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);
        retVal = sDataShareHelper_->Update(modifyAlbumUri, {}, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to modify the album");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::DeleteAlbum(const int32_t albumId)
{
    int32_t retVal = E_FAIL;

    if (sDataShareHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_DELETEALBUM + "/" +
            to_string(albumId));
        retVal = sDataShareHelper_->Delete(deleteAlbumUri, {});
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to delete the album");
        }
    }

    return retVal;
}

unique_ptr<FetchResult<FileAsset>> MediaLibraryManager::GetAlbumFileAssets(const int32_t albumId,
    const MediaFetchOptions &option)
{
    unique_ptr<FetchResult<FileAsset>> fetchFileResult = nullptr;
    DataSharePredicates predicates;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(option);

    if (sDataShareHelper_ != nullptr) {
        string prefix = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
        AppendFetchOptionSelection(fetchOptions.selections, prefix);
        fetchOptions.selectionArgs.emplace_back(std::to_string(albumId));
        fetchOptions.selectionArgs.emplace_back(std::to_string(MEDIA_TYPE_ALBUM));

        predicates.SetWhereClause(fetchOptions.selections);
        predicates.SetWhereArgs(fetchOptions.selectionArgs);
        predicates.SetOrder(fetchOptions.order);

        vector<string> columns;
        Uri uri(MEDIALIBRARY_DATA_URI);

        auto resultSet =
            sDataShareHelper_->Query(uri, predicates, columns);

        fetchFileResult = make_unique<FetchResult<FileAsset>>(resultSet);
        if (fetchFileResult == nullptr) {
            MEDIA_ERR_LOG("Failed to obtain fetch file result");
        }
    }

    return fetchFileResult;
}

int32_t MediaLibraryManager::QueryTotalSize(MediaVolume &outMediaVolume)
{
    if (sDataShareHelper_ == nullptr) {
        MEDIA_ERR_LOG("sDataShareHelper_ is null");
        return E_FAIL;
    }
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    DataSharePredicates predicates;
    auto queryResultSet = sDataShareHelper_->Query(uri, predicates, columns);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("queryResultSet is null!");
        return E_FAIL;
    }
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed");
        return E_HAS_DB_ERROR;
    }
    MEDIA_INFO_LOG("count = %{public}d", (int)count);
    if (count >= 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int mediatype = get<int32_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE,
                queryResultSet, TYPE_INT32));
            int64_t size = get<int64_t>(ResultSetUtils::GetValFromColumn(MEDIA_DATA_DB_SIZE,
                queryResultSet, TYPE_INT64));
            outMediaVolume.SetSize(mediatype, size);
        }
    }
    MEDIA_INFO_LOG("Size:Files:%{public}" PRId64 " Videos:%{public}" PRId64 " Images:%{public} " PRId64
        " Audio:%{public}" PRId64,
        outMediaVolume.GetFilesSize(), outMediaVolume.GetVideosSize(),
        outMediaVolume.GetImagesSize(), outMediaVolume.GetAudiosSize());
    return E_SUCCESS;
}
} // namespace Media
} // namespace OHOS
