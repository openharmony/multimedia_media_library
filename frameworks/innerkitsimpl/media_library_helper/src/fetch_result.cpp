/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "FetchResult"

#include "fetch_result.h"
#include "album_asset.h"
#include "media_log.h"
#include "medialibrary_tracer.h"

using namespace std;

namespace OHOS {
namespace Media {
static const unordered_map<string, ResultSetDataType> RESULT_TYPE_MAP = {
    { MEDIA_DATA_DB_ID, TYPE_INT32 },
    { MEDIA_DATA_DB_NAME, TYPE_STRING },
    { MEDIA_DATA_DB_RELATIVE_PATH, TYPE_STRING },
    { MEDIA_DATA_DB_MEDIA_TYPE, TYPE_INT32 },
    { MEDIA_DATA_DB_PARENT_ID, TYPE_INT32 },
    { MEDIA_DATA_DB_SIZE, TYPE_INT64 },
    { MEDIA_DATA_DB_DATE_ADDED, TYPE_INT64 },
    { MEDIA_DATA_DB_DATE_MODIFIED, TYPE_INT64 },
    { MEDIA_DATA_DB_DATE_TAKEN, TYPE_INT64 },
    { MEDIA_DATA_DB_FILE_PATH, TYPE_STRING },
    { MEDIA_DATA_DB_MIME_TYPE, TYPE_STRING },
    { MEDIA_DATA_DB_TITLE, TYPE_STRING },
    { MEDIA_DATA_DB_ARTIST, TYPE_STRING },
    { MEDIA_DATA_DB_ALBUM, TYPE_STRING },
    { MEDIA_DATA_DB_WIDTH, TYPE_INT32 },
    { MEDIA_DATA_DB_HEIGHT, TYPE_INT32 },
    { MEDIA_DATA_DB_DURATION, TYPE_INT32 },
    { MEDIA_DATA_DB_ORIENTATION, TYPE_INT32 },
    { MEDIA_DATA_DB_BUCKET_ID, TYPE_INT32 },
    { MEDIA_DATA_DB_BUCKET_NAME, TYPE_STRING },
    { MEDIA_DATA_DB_TIME_PENDING, TYPE_INT64 },
    { MEDIA_DATA_DB_IS_PENDING, TYPE_INT32 },
    { MEDIA_DATA_DB_IS_FAV, TYPE_INT32 },
    { MEDIA_DATA_DB_DATE_TRASHED, TYPE_INT64 },
    { MEDIA_DATA_DB_SELF_ID, TYPE_STRING },
    { MEDIA_DATA_DB_RECYCLE_PATH, TYPE_STRING },
    { MEDIA_DATA_DB_IS_TRASH, TYPE_INT32 },
    { MEDIA_DATA_DB_AUDIO_ALBUM, TYPE_STRING },
};

template <class T>
FetchResult<T>::FetchResult(const shared_ptr<DataShare::DataShareResultSet> &resultset)
{
    count_ = 0;
    if (resultset != nullptr) {
        resultset->GetRowCount(count_);
    }
    isContain_ = count_ > 0;
    isClosed_ = false;
    resultset_ = resultset;
    networkId_ = "";
    resultNapiType_ = ResultNapiType::TYPE_NAPI_MAX;
    if (std::is_same<T, FileAsset>::value) {
        fetchResType_ = FetchResType::TYPE_FILE;
    } else if (std::is_same<T, AlbumAsset>::value) {
        fetchResType_ = FetchResType::TYPE_ALBUM;
    } else if (std::is_same<T, SmartAlbumAsset>::value) {
        fetchResType_ = FetchResType::TYPE_SMARTALBUM;
    } else {
        MEDIA_ERR_LOG("unsupported FetchResType");
        fetchResType_ = FetchResType::TYPE_FILE;
    }
}

template <class T>
// empty constructor napi
FetchResult<T>::FetchResult()
    : isContain_(false), isClosed_(false), count_(0), resultNapiType_(ResultNapiType::TYPE_NAPI_MAX),
      resultset_(nullptr) {}

template <class T>
FetchResult<T>::~FetchResult() {}

template <class T>
void FetchResult<T>::Close()
{
    isClosed_ = true;
}

template <class T>
bool FetchResult<T>::IsContain()
{
    return isContain_;
}

template <class T>
int32_t FetchResult<T>::GetCount()
{
    return count_;
}

template <class T>
bool FetchResult<T>::IsClosed()
{
    return isClosed_;
}

template <class T>
void FetchResult<T>::SetInfo(unique_ptr<FetchResult<T>> &fetch)
{
    isContain_ = fetch->isContain_;
    isClosed_ = fetch->isClosed_;
    count_ = fetch->count_;
    networkId_ = fetch->networkId_;
    resultNapiType_ = fetch->resultNapiType_;
    typeMask_ = fetch->typeMask_;
}

template <class T>
void FetchResult<T>::SetNetworkId(const string &networkId)
{
    networkId_ = networkId;
}

template <class T>
unique_ptr<T> FetchResult<T>::GetObjectAtPosition(int32_t index)
{
    if ((index < 0) || (index > (count_ - 1)) || (resultset_ == nullptr)) {
        MEDIA_ERR_LOG("index not proper or rs is null");
        return nullptr;
    }

    if (resultset_->GoToRow(index) != 0) {
        MEDIA_ERR_LOG("failed to go to row at index pos");
        return nullptr;
    }

    return GetObject();
}

template <class T>
unique_ptr<T> FetchResult<T>::GetFirstObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToFirstRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|first row failed");
        return nullptr;
    }

    return GetObject();
}

template <class T>
unique_ptr<T> FetchResult<T>::GetNextObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToNextRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|go to next row failed");
        return nullptr;
    }

    return GetObject();
}

template <class T>
unique_ptr<T> FetchResult<T>::GetLastObject()
{
    if ((resultset_ == nullptr) || (resultset_->GoToLastRow() != 0)) {
        MEDIA_ERR_LOG("resultset is null|go to last row failed");
        return nullptr;
    }

    return GetObject();
}

template <class T>
bool FetchResult<T>::IsAtLastRow()
{
    if (resultset_ == nullptr) {
        MEDIA_ERR_LOG("resultset null");
        return false;
    }

    bool retVal = false;
    resultset_->IsAtLastRow(retVal);
    return retVal;
}

variant<int32_t, int64_t, string> ReturnDefaultOnError(string errMsg, ResultSetDataType dataType)
{
    MEDIA_ERR_LOG("%{public}s", errMsg.c_str());
    if (dataType == TYPE_STRING) {
        return "";
    } else if (dataType == TYPE_INT64) {
        return static_cast<int64_t>(0);
    } else {
        return 0;
    }
}

template <class T>
variant<int32_t, int64_t, string> FetchResult<T>::GetRowValFromColumn(string columnName, ResultSetDataType dataType,
    shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    if ((resultset_ == nullptr) && (resultSet == nullptr)) {
        return ReturnDefaultOnError("Resultset is null", dataType);
    }
    int index;
    int status;
    if (resultSet) {
        status = resultSet->GetColumnIndex(columnName, index);
    } else {
        status = resultset_->GetColumnIndex(columnName, index);
    }
    if (status != NativeRdb::E_OK) {
        ReturnDefaultOnError("failed to obtain the index", dataType);
    }
    return GetValByIndex(index, dataType, resultSet);
}

template <class T>
variant<int32_t, int64_t, string> FetchResult<T>::GetValByIndex(int32_t index, ResultSetDataType dataType,
    shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    if ((resultset_ == nullptr) && (resultSet == nullptr)) {
        return ReturnDefaultOnError("Resultset is null", dataType);
    }

    variant<int32_t, int64_t, string> cellValue;
    int integerVal = 0;
    string stringVal = "";
    int64_t longVal = 0;
    int status;
    switch (dataType) {
        case TYPE_STRING:
            if (resultSet) {
                status = resultSet->GetString(index, stringVal);
            } else {
                status = resultset_->GetString(index, stringVal);
            }
            cellValue = stringVal;
            break;
        case TYPE_INT32:
            if (resultSet) {
                status = resultSet->GetInt(index, integerVal);
            } else {
                status = resultset_->GetInt(index, integerVal);
            }
            cellValue = integerVal;
            break;
        case TYPE_INT64:
            if (resultSet) {
                status = resultSet->GetLong(index, longVal);
            } else {
                status = resultset_->GetLong(index, longVal);
            }
            cellValue = longVal;
            break;
        default:
            MEDIA_ERR_LOG("not match  dataType %{public}d", dataType);
            break;
    }

    return cellValue;
}

static string GetFileMediaTypeUri(MediaType mediaType, const string &networkId)
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

static void MediaTypeToMask(MediaType mediaType, std::string &typeMask)
{
    typeMask.resize(TYPE_MASK_STRING_SIZE, TYPE_MASK_BIT_DEFAULT);
    if ((mediaType >= MEDIA_TYPE_FILE) && (mediaType <= MEDIA_TYPE_AUDIO)) {
        typeMask[std::get<POS_TYPE_MASK_STRING_INDEX>(MEDIA_TYPE_TUPLE_VEC[mediaType])] = TYPE_MASK_BIT_SET;
    }
}

static void UriAddFragmentTypeMask(std::string &uri, const std::string &typeMask)
{
    if (!typeMask.empty()) {
        uri += "#" + URI_PARAM_KEY_TYPE + ":" + typeMask;
    }
}

template<class T>
int32_t FetchResult<T>::GetFileCount(const shared_ptr<DataShare::DataShareResultSet> &resultSet)
{
    int32_t count = 1;
    if (resultSet) {
        string name;
        resultSet->GetColumnName(0, name);
        if (name.find("count(") != string::npos) {
            resultSet->GetInt(0, count);
        }
    }
    return count;
}

template<class T>
void FetchResult<T>::SetFileAsset(FileAsset *fileAsset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    if ((resultset_ == nullptr) && (resultSet == nullptr)) {
        MEDIA_ERR_LOG("SetFileAsset fail, result is nullptr");
        return;
    }
    vector<string> columnNames;
    if (resultSet != nullptr) {
        resultSet->GetAllColumnNames(columnNames);
    } else {
        resultset_->GetAllColumnNames(columnNames);
    }
    int32_t index = -1;
    auto &map = fileAsset->GetMemberMap();
    for (const auto &name : columnNames) {
        index++;
        if (RESULT_TYPE_MAP.count(name) == 0) {
            continue;
        }
        auto memberType = RESULT_TYPE_MAP.at(name);
        map.emplace(move(name), move(GetValByIndex(index, memberType, resultSet)));
    }
    fileAsset->SetResultNapiType(resultNapiType_);
    fileAsset->SetCount(GetFileCount(resultset_));
    string typeMask;
    MediaTypeToMask(fileAsset->GetMediaType(), typeMask);
    string uri = GetFileMediaTypeUri(fileAsset->GetMediaType(), networkId_) + "/" + to_string(fileAsset->GetId());
    if (resultNapiType_ == ResultNapiType::TYPE_USERFILE_MGR) {
        UriAddFragmentTypeMask(uri, typeMask);
    }
    fileAsset->SetUri(uri);
}

template<class T>
void FetchResult<T>::GetObjectFromAsset(FileAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    SetFileAsset(asset, resultSet);
}

template<class T>
void FetchResult<T>::GetObjectFromAsset(AlbumAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    SetAlbumAsset(asset, resultSet);
}

template<class T>
void FetchResult<T>::GetObjectFromAsset(SmartAlbumAsset *asset, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    SetSmartAlbumAsset(asset, resultSet);
}

template<class T>
unique_ptr<T> FetchResult<T>::GetObject(shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    MediaLibraryTracer tracer;
    tracer.Start("FetchResult::GetObject");
    unique_ptr<T> asset = make_unique<T>();
    GetObjectFromAsset(asset.get(), resultSet);
    return asset;
}

template <class T>
unique_ptr<T> FetchResult<T>::GetObject()
{
    shared_ptr<NativeRdb::AbsSharedResultSet> resultSet = nullptr;
    return GetObject(resultSet);
}

template <class T>
unique_ptr<T> FetchResult<T>::GetObjectFromRdb(shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet, int idx)
{
    if ((resultSet == nullptr) || (resultSet->GoToFirstRow() != 0) || (resultSet->GoTo(idx))) {
        MEDIA_ERR_LOG("resultset is null|first row failed");
        return nullptr;
    }

    return GetObject(resultSet);
}

template<class T>
void FetchResult<T>::SetAlbumAsset(AlbumAsset *albumData, shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    // Get album id index and value
    albumData->SetAlbumId(get<int32_t>(GetRowValFromColumn(MEDIA_DATA_DB_BUCKET_ID, TYPE_INT32, resultSet)));

    // Get album title index and value
    albumData->SetAlbumName(get<string>(GetRowValFromColumn(MEDIA_DATA_DB_TITLE, TYPE_STRING, resultSet)));

    // Get album asset count index and value
    albumData->SetCount(get<int32_t>(GetRowValFromColumn(MEDIA_DATA_DB_COUNT, TYPE_INT32, resultSet)));
    albumData->SetAlbumUri(GetFileMediaTypeUri(MEDIA_TYPE_ALBUM, networkId_) + "/" +
        to_string(albumData->GetAlbumId()));
    // Get album relativePath index and value
    albumData->SetAlbumRelativePath(get<string>(GetRowValFromColumn(MEDIA_DATA_DB_RELATIVE_PATH,
        TYPE_STRING, resultSet)));
    albumData->SetAlbumDateModified(get<int64_t>(GetRowValFromColumn(MEDIA_DATA_DB_DATE_MODIFIED,
        TYPE_INT64, resultSet)));

    albumData->SetResultNapiType(resultNapiType_);
    albumData->SetAlbumTypeMask(typeMask_);
}

template<class T>
void FetchResult<T>::SetSmartAlbumAsset(SmartAlbumAsset* smartAlbumData,
    std::shared_ptr<NativeRdb::AbsSharedResultSet> &resultSet)
{
    smartAlbumData->SetAlbumId(get<int32_t>(GetRowValFromColumn(SMARTALBUM_DB_ID, TYPE_INT32, resultSet)));
    smartAlbumData->SetAlbumName(get<string>(GetRowValFromColumn(SMARTALBUM_DB_NAME, TYPE_STRING, resultSet)));
    smartAlbumData->SetAlbumCapacity(get<int32_t>(GetRowValFromColumn(SMARTALBUM_DB_CAPACITY, TYPE_INT32, resultSet)));
    smartAlbumData->SetResultNapiType(resultNapiType_);
    smartAlbumData->SetTypeMask(typeMask_);
}

template class FetchResult<FileAsset>;
template class FetchResult<AlbumAsset>;
template class FetchResult<SmartAlbumAsset>;
}  // namespace Media
}  // namespace OHOS
