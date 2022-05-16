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

#include "media_library_manager.h"
#include "datashare_predicates.h"
#include "datashare_abs_result_set.h"

#include "media_log.h"

using namespace std;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
shared_ptr<DataShare::DataShareHelper> MediaLibraryManager::sAbilityHelper_ = nullptr;

MediaLibraryManager *MediaLibraryManager::GetMediaLibraryManager()
{
    static MediaLibraryManager mediaLibMgr;
    return &mediaLibMgr;
}

void MediaLibraryManager::InitMediaLibraryManager(const shared_ptr<AppExecFwk::Context> context)
{
    AppExecFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "MediaDataService");
    if (sAbilityHelper_ == nullptr) {
        sAbilityHelper_ = AppExecFwk::MediaDataHelper::Creator(context, want, std::make_shared<Uri>("mediadata://media"));
    }
}

void MediaLibraryManager::InitMediaLibraryManager(const sptr<IRemoteObject> &token)
{
    AppExecFwk::Want want;
    want.SetElementName("com.ohos.medialibrary.medialibrarydata", "MediaDataService");
    if (sAbilityHelper_ == nullptr) {
        //sAbilityHelper_ = DataShare::DataShareHelper::Creator(context, make_shared<Uri>(strUri));
    }
}

static void UpdateFetchOptionSelection(std::string &selection, const std::string &prefix)
{
    if (!prefix.empty()) {
        if (!selection.empty()) {
            selection = prefix + "AND (" + selection + ")";
        } else {
            selection = prefix;
        }
    }
}
unique_ptr<FetchResult> MediaLibraryManager::GetFileAssets(const MediaFetchOptions &fetchOps)
{
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    vector<string> columns;
    DataSharePredicates predicates;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(fetchOps);

    string prefix = MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
    UpdateFetchOptionSelection(fetchOptions.selections, prefix);
    fetchOptions.selectionArgs.insert(fetchOptions.selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(fetchOptions.selections);
    predicates.SetWhereArgs(fetchOptions.selectionArgs);
    predicates.SetOrder(fetchOptions.order);

    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = nullptr;

    if (sAbilityHelper_ == nullptr
        || ((resultSet = sAbilityHelper_->Query(uri, columns, predicates)) == nullptr)) {
        MEDIA_ERR_LOG("Resultset retrieval failure caused Query operation to fail");
    } else {
        // Create FetchResult object using the contents of resultSet
        fetchFileResult = make_unique<FetchResult>(move(resultSet));
        if (fetchFileResult == nullptr) {
            MEDIA_ERR_LOG("No fetch file result found!");
        }
    }

    return fetchFileResult;
}

variant<int32_t, string> GetValFromColumn(string columnName,
    shared_ptr<DataShareResultSet> &resultSet)
{
    variant<int32_t, string> cellValue;
    /*
    int32_t index;
    ColumnType type;
    int33_t integerVal;
    string stringVal;
    CHECK_AND_RETURN_RET_LOG(resultSet != nullptr, cellValue, "resultSet != nullptr");
    resultSet->GetColumnIndex(columnName, index);
    resultSet->GetColumnType(index, type);
    switch (type) {
        case ColumnType::TYPE_STRING:
            resultSet->GetString(index, stringVal);
            cellValue = stringVal;
            break;
        case ColumnType::TYPE_INTEGER:
            resultSet->GetInt(index, integerVal);
            cellValue = integerVal;
            break;
        default:
            break;
    }
    */

    return cellValue;
}

int64_t GetLongValFromColumn(string columnName, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    int index = 0;
    int64_t longVal = 0;
    resultSet->GetColumnIndex(columnName, index);
    resultSet->GetLong(index, longVal);
    return longVal;
}

vector<unique_ptr<AlbumAsset>> MediaLibraryManager::GetAlbums(const MediaFetchOptions &fetchOps)
{
    vector<unique_ptr<AlbumAsset>> albums;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(fetchOps);
    DataSharePredicates predicates;

    if (sAbilityHelper_ == nullptr) {
        MEDIA_ERR_LOG("Ability Helper is null");
        return albums;
    }

    UpdateFetchOptionSelection(fetchOptions.selections, MEDIA_DATA_DB_MEDIA_TYPE + " = ? ");
    fetchOptions.selectionArgs.insert(fetchOptions.selectionArgs.begin(), to_string(MEDIA_TYPE_ALBUM));

    predicates.SetWhereClause(fetchOptions.selections);
    predicates.SetWhereArgs(fetchOptions.selectionArgs);
    if (!fetchOptions.order.empty()) {
        predicates.SetOrder(fetchOptions.order);
    }

    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI);
    shared_ptr<DataShareResultSet> resultSet = sAbilityHelper_->Query(
        uri, columns, predicates);

    if (resultSet != nullptr) {
        while (resultSet->GoToNextRow() == NativeRdb::E_OK) {
            unique_ptr<AlbumAsset> albumData = make_unique<AlbumAsset>();
            if (albumData != nullptr) {
                // Get album id index and value
                albumData->SetAlbumId(get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_ID, resultSet)));

                // Get album name index and value
                albumData->SetAlbumName(get<string>(GetValFromColumn(MEDIA_DATA_DB_ALBUM_NAME, resultSet)));

                // Get album path index and value
                albumData->SetAlbumPath(get<string>(GetValFromColumn(MEDIA_DATA_DB_FILE_PATH, resultSet)));

                // Get album relative path index and value
                albumData->SetAlbumRelativePath(get<string>(GetValFromColumn(
                    MEDIA_DATA_DB_RELATIVE_PATH, resultSet)));

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
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, fileAssetObj.GetPath());
    valuesBucket.PutInt(MEDIA_DATA_DB_MEDIA_TYPE, fileAssetObj.GetMediaType());

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CREATEASSET);

        int32_t index = sAbilityHelper_->Insert(createAssetUri, valuesBucket);
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
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, fileAssetObj.GetPath());

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri updateAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_MODIFYASSET);

        retVal = sAbilityHelper_->Insert(updateAssetUri, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to modify the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::DeleteAsset(const string &uri)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_DELETEASSET);

        retVal = sAbilityHelper_->Insert(deleteAssetUri, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to delete the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::OpenAsset(const string &uri, string &mode)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);
    valuesBucket.PutString(MEDIA_FILEMODE, mode);

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri openAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_OPENASSET);

        retVal = sAbilityHelper_->Insert(openAssetUri, valuesBucket);
        if (retVal <= 0) {
            MEDIA_ERR_LOG("Failed to open the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::CloseAsset(const string &uri, const int32_t fd)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_URI, uri);

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri closeAssetUri(abilityUri + "/" + MEDIA_FILEOPRN + "/" + MEDIA_FILEOPRN_CLOSEASSET);

        if (close(fd) == DATA_ABILITY_SUCCESS) {
            retVal = sAbilityHelper_->Insert(closeAssetUri, valuesBucket);
        }

        if (retVal == DATA_ABILITY_FAIL) {
            MEDIA_ERR_LOG("Failed to close the file");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::CreateAlbum(const AlbumAsset &albumNapiObj)
{
    int32_t albumId = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, albumNapiObj.GetAlbumPath());

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri createAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_CREATEALBUM);

        albumId = sAbilityHelper_->Insert(createAlbumUri, valuesBucket);
        if (albumId < 0) {
            MEDIA_ERR_LOG("Failed to create the album");
        }
    }

    return albumId;
}

int32_t MediaLibraryManager::ModifyAlbum(const int32_t albumId, const AlbumAsset &albumNapiObj)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);
    valuesBucket.PutString(MEDIA_DATA_DB_ALBUM_NAME, albumNapiObj.GetAlbumName());

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri modifyAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_MODIFYALBUM);

        retVal = sAbilityHelper_->Insert(modifyAlbumUri, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to modify the album");
        }
    }

    return retVal;
}

int32_t MediaLibraryManager::DeleteAlbum(const int32_t albumId)
{
    int32_t retVal = DATA_ABILITY_FAIL;
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutInt(MEDIA_DATA_DB_ID, albumId);

    if (sAbilityHelper_ != nullptr) {
        string abilityUri = MEDIALIBRARY_DATA_URI;
        Uri deleteAlbumUri(abilityUri + "/" + MEDIA_ALBUMOPRN + "/" + MEDIA_ALBUMOPRN_DELETEALBUM);

        retVal = sAbilityHelper_->Insert(deleteAlbumUri, valuesBucket);
        if (retVal < 0) {
            MEDIA_ERR_LOG("Failed to delete the album");
        }
    }

    return retVal;
}

unique_ptr<FetchResult> MediaLibraryManager::GetAlbumFileAssets(const int32_t albumId, const MediaFetchOptions &option)
{
    unique_ptr<FetchResult> fetchFileResult = nullptr;
    DataSharePredicates predicates;
    MediaFetchOptions fetchOptions = const_cast<MediaFetchOptions &>(option);

    if (sAbilityHelper_ != nullptr) {
        string prefix = MEDIA_DATA_DB_PARENT_ID + " = ? AND " + MEDIA_DATA_DB_MEDIA_TYPE + " <> ? ";
        UpdateFetchOptionSelection(fetchOptions.selections, prefix);
        fetchOptions.selectionArgs.insert(fetchOptions.selectionArgs.begin(), std::to_string(MEDIA_TYPE_ALBUM));
        fetchOptions.selectionArgs.insert(fetchOptions.selectionArgs.begin(), std::to_string(albumId));

        predicates.SetWhereClause(fetchOptions.selections);
        predicates.SetWhereArgs(fetchOptions.selectionArgs);
        predicates.SetOrder(fetchOptions.order);

        vector<string> columns;
        Uri uri(MEDIALIBRARY_DATA_URI);

        shared_ptr<DataShareResultSet> resultSet =
            sAbilityHelper_->Query(uri, columns, predicates);

        fetchFileResult = make_unique<FetchResult>(resultSet);
        if (fetchFileResult == nullptr) {
            MEDIA_ERR_LOG("Failed to obtain fetch file result");
        }
    }

    return fetchFileResult;
}

int32_t MediaLibraryManager::QueryTotalSize(MediaVolume &outMediaVolume)
{
    MEDIA_DEBUG_LOG("QueryTotalSize start");
    if (sAbilityHelper_ == nullptr) {
        MEDIA_ERR_LOG("sAbilityHelper_ is null");
        return DATA_ABILITY_FAIL;
    }
    vector<string> columns;
    Uri uri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_QUERYOPRN + "/" + MEDIA_QUERYOPRN_QUERYVOLUME);
    DataAbilityPredicates predicates;
    shared_ptr<AbsSharedResultSet> queryResultSet = sAbilityHelper_->Query(uri, columns, predicates);
    if (queryResultSet == nullptr) {
        MEDIA_ERR_LOG("queryResultSet is null!");
        return DATA_ABILITY_FAIL;
    }
    auto count = 0;
    auto ret = queryResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("get rdbstore failed %{public}d", ret);
        return DATA_ABILITY_HAS_DB_ERROR;
    }
    MEDIA_DEBUG_LOG("count = %{public}d", (int)count);
    if (count >= 0) {
        while (queryResultSet->GoToNextRow() == NativeRdb::E_OK) {
            int mediatype = get<int32_t>(GetValFromColumn(MEDIA_DATA_DB_MEDIA_TYPE, queryResultSet));
            int64_t size = GetLongValFromColumn(MEDIA_DATA_DB_SIZE, queryResultSet);
            MEDIA_DEBUG_LOG("mediatype = %{public}d, size = %{public}lld", mediatype, size);
            outMediaVolume.SetSize(mediatype, size);
        }
    }
    MEDIA_INFO_LOG("FilesSize:%{public}lld, VideosSize:%{public}lld, ImagesSize:%{public}lld, AudiosSize:%{public}lld",
        outMediaVolume.GetFilesSize(), outMediaVolume.GetVideosSize(), outMediaVolume.GetImagesSize(),
        outMediaVolume.GetAudiosSize());
    return DATA_ABILITY_SUCCESS;
}
} // namespace Media
} // namespace OHOS
