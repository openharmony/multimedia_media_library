/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "media_ani_native_impl.h"

#include <string>
#include <memory>

#include "medialibrary_ani_enum_comm.h"
#include "medialibrary_ani_log.h"
#include "media_device_column.h"
#include "photo_album_column.h"
#include "media_file_uri.h"
#include "media_file_utils.h"
#include "medialibrary_errno.h"
#include "medialibrary_db_const.h"
#include "userfile_client.h"

using namespace std;
using namespace OHOS::DataShare;

namespace OHOS {
namespace Media {
std::vector<std::unique_ptr<FileAsset>> MediaAniNativeImpl::GetAssetsSync(
    const std::vector<std::string> &fetchColumns,
    std::shared_ptr<OHOS::DataShare::DataShareAbsPredicates> predicate)
{
    std::vector<std::unique_ptr<FileAsset>> result;

    std::shared_ptr<MediaLibraryAsyncContext> context = GetAssetsContext(fetchColumns, predicate);
    if (context == nullptr) {
        ANI_ERR_LOG("GetAssetsContext failed");
        return result;
    }

    if (!PhotoAccessGetAssetsExecuteSync(context, result)) {
        ANI_ERR_LOG("PhotoAccessGetAssetsExecuteSync failed");
    }

    return result;
}

std::unique_ptr<FetchResult<FileAsset>> MediaAniNativeImpl::GetAssets(
    const std::vector<std::string> &fetchColumns,
    std::shared_ptr<DataShare::DataShareAbsPredicates> predicate)
{
    std::shared_ptr<MediaLibraryAsyncContext> context = GetAssetsContext(fetchColumns, predicate);
    if (context == nullptr) {
        ANI_ERR_LOG("GetAssetsContext failed");
        return nullptr;
    }

    if (!PhotoAccessGetAssetsExecute(context)) {
        ANI_ERR_LOG("PhotoAccessGetAssetsExecute failed");
        return nullptr;
    }

    return std::move(context->fetchFileResult);
}

std::shared_ptr<MediaLibraryAsyncContext> MediaAniNativeImpl::GetAssetsContext(
    const std::vector<std::string> &fetchColumns,
    std::shared_ptr<DataShare::DataShareAbsPredicates> predicate)
{
    std::shared_ptr<MediaLibraryAsyncContext> context = std::make_shared<MediaLibraryAsyncContext>();
    if (!HandleSpecialPredicate(context, predicate, ASSET_FETCH_OPT)) {
        ANI_ERR_LOG("HandleSpecialPredicate failed");
        return nullptr;
    }
    if (!GetLocationPredicate(context, predicate)) {
        ANI_ERR_LOG("GetLocationPredicate failed");
        return nullptr;
    }

    context->fetchColumn = fetchColumns;
    if (!AddDefaultAssetColumns(context->fetchColumn, PhotoColumn::IsPhotoColumn)) {
        ANI_ERR_LOG("AddDefaultAssetColumns failed");
        return nullptr;
    }

    auto &predicates = context->predicates;
    predicates.And()->EqualTo(MediaColumn::MEDIA_DATE_TRASHED, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_TIME_PENDING, to_string(0));
    predicates.And()->EqualTo(MediaColumn::MEDIA_HIDDEN, to_string(0));
    predicates.And()->EqualTo(PhotoColumn::PHOTO_IS_TEMP, to_string(false));
    predicates.EqualTo(PhotoColumn::PHOTO_BURST_COVER_LEVEL,
        to_string(static_cast<int32_t>(BurstCoverLevelType::COVER)));

    return context;
}

static bool HandleSpecialDateTypePredicate(const OperationItem &item,
    vector<OperationItem> &operations, const FetchOptionType &fetchOptType)
{
    constexpr int32_t fieldIdx = 0;
    constexpr int32_t valueIdx = 1;
    vector<string>dateTypes = { MEDIA_DATA_DB_DATE_ADDED, MEDIA_DATA_DB_DATE_TRASHED, MEDIA_DATA_DB_DATE_MODIFIED,
        MEDIA_DATA_DB_DATE_TAKEN};
    string dateType = item.GetSingle(fieldIdx);
    auto it = find(dateTypes.begin(), dateTypes.end(), dateType);
    if (it != dateTypes.end() && item.operation != DataShare::ORDER_BY_ASC &&
        item.operation != DataShare::ORDER_BY_DESC) {
        dateType += "_s";
        operations.push_back({ item.operation, { dateType, static_cast<double>(item.GetSingle(valueIdx)) } });
        return true;
    }
    if (DATE_TRANSITION_MAP.count(dateType) != 0) {
        dateType = DATE_TRANSITION_MAP.at(dateType);
        operations.push_back({ item.operation, { dateType, static_cast<double>(item.GetSingle(valueIdx)) } });
        return true;
    }
    return false;
}

bool MediaAniNativeImpl::HandleSpecialPredicate(std::shared_ptr<MediaLibraryAsyncContext> context,
    std::shared_ptr<DataShare::DataShareAbsPredicates> predicate, const FetchOptionType &fetchOptType)
{
    constexpr int32_t fieldIdx = 0;
    constexpr int32_t valueIdx = 1;
    std::vector<OperationItem> operations;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        if (item.singleParams.empty()) {
            operations.push_back(item);
            continue;
        }
        if (HandleSpecialDateTypePredicate(item, operations, fetchOptType)) {
            continue;
        }
        // change uri ->file id
        // get networkid
        // replace networkid with file id
        if (static_cast<string>(item.GetSingle(fieldIdx)) == DEVICE_DB_NETWORK_ID) {
            if (item.operation != DataShare::EQUAL_TO || static_cast<string>(item.GetSingle(valueIdx)).empty()) {
                ANI_ERR_LOG("DEVICE_DB_NETWORK_ID predicates not support %{public}d", item.operation);
                return false;
            }
            context->networkId = static_cast<string>(item.GetSingle(valueIdx));
            continue;
        }
        if (static_cast<string>(item.GetSingle(fieldIdx)) == MEDIA_DATA_DB_URI) {
            if (item.operation != DataShare::EQUAL_TO) {
                ANI_ERR_LOG("MEDIA_DATA_DB_URI predicates not support %{public}d", item.operation);
                return false;
            }
            string uri = static_cast<string>(item.GetSingle(valueIdx));
            MediaFileUri::RemoveAllFragment(uri);
            MediaFileUri fileUri(uri);
            context->uri = uri;
            if ((fetchOptType != ALBUM_FETCH_OPT) && (!fileUri.IsApi10())) {
                fileUri = MediaFileUri(MediaFileUtils::GetRealUriFromVirtualUri(uri));
            }
            context->networkId = fileUri.GetNetworkId();
            string field = (fetchOptType == ALBUM_FETCH_OPT) ? PhotoAlbumColumns::ALBUM_ID : MEDIA_DATA_DB_ID;
            operations.push_back({ item.operation, { field, fileUri.GetFileId() } });
            continue;
        }
        if (static_cast<string>(item.GetSingle(fieldIdx)) == PENDING_STATUS) {
            // do not query pending files below API11
            continue;
        }
        if (LOCATION_PARAM_MAP.find(static_cast<string>(item.GetSingle(fieldIdx))) != LOCATION_PARAM_MAP.end()) {
            continue;
        }
        operations.push_back(item);
    }
    context->predicates = DataSharePredicates(move(operations));
    return true;
}

bool MediaAniNativeImpl::GetLocationPredicate(std::shared_ptr<MediaLibraryAsyncContext> context,
    shared_ptr<DataShareAbsPredicates> predicate)
{
    constexpr int32_t fieldIdx = 0;
    constexpr int32_t valueIdx = 1;
    map<string, string> locationMap;
    auto &items = predicate->GetOperationList();
    for (auto &item : items) {
        if (item.singleParams.empty()) {
            continue;
        }
        if (LOCATION_PARAM_MAP.find(static_cast<string>(item.GetSingle(fieldIdx))) != LOCATION_PARAM_MAP.end()) {
            if (item.operation != DataShare::EQUAL_TO) {
                ANI_ERR_LOG("location predicates not support %{public}d", item.operation);
                return false;
            }
            string param = static_cast<string>(item.GetSingle(fieldIdx));
            string value = static_cast<string>(item.GetSingle(valueIdx));
            locationMap.insert(make_pair(param, value));
            if (param == DIAMETER) {
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::GREATER_THAN_OR_EQUAL_TO) {
                context->predicates.GreaterThanOrEqualTo(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::LESS_THAN) {
                context->predicates.LessThan(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
            if (LOCATION_PARAM_MAP.at(param).second == DataShare::EQUAL_TO) {
                context->predicates.EqualTo(LOCATION_PARAM_MAP.at(param).first, value);
                continue;
            }
        }
    }

    if (locationMap.count(DIAMETER) == 1 && locationMap.count(START_LATITUDE) == 1
        && locationMap.count(START_LONGITUDE) == 1) {
        // 0.5:Used for rounding down
        string latitudeIndex = "round((latitude - " + locationMap.at(START_LATITUDE) + ") / " +
            locationMap.at(DIAMETER) + " - 0.5)";
        string longitudeIndex = "round((longitude - " + locationMap.at(START_LONGITUDE) + ") / " +
            locationMap.at(DIAMETER) + " - 0.5)";
        string albumName = LATITUDE + "||'_'||" + LONGITUDE + "||'_'||" + latitudeIndex + "||'_'||" +
            longitudeIndex + " AS " + ALBUM_NAME;
        context->fetchColumn.push_back(albumName);
        string locationGroup = latitudeIndex + "," + longitudeIndex;
        context->predicates.GroupBy({ locationGroup });
    }
    return true;
}

bool MediaAniNativeImpl::AddDefaultAssetColumns(vector<string> &fetchColumn,
    function<bool(const string &columnName)> isValidColumn, const PhotoAlbumSubType subType)
{
    auto validFetchColumns = MediaColumn::DEFAULT_FETCH_COLUMNS;
    validFetchColumns.insert(PhotoColumn::DEFAULT_FETCH_COLUMNS.begin(), PhotoColumn::DEFAULT_FETCH_COLUMNS.end());

    switch (subType) {
        case PhotoAlbumSubType::FAVORITE:
            validFetchColumns.insert(MediaColumn::MEDIA_IS_FAV);
            break;
        case PhotoAlbumSubType::VIDEO:
            validFetchColumns.insert(MediaColumn::MEDIA_TYPE);
            break;
        case PhotoAlbumSubType::HIDDEN:
            validFetchColumns.insert(MediaColumn::MEDIA_HIDDEN);
            break;
        case PhotoAlbumSubType::TRASH:
            validFetchColumns.insert(MediaColumn::MEDIA_DATE_TRASHED);
            break;
        case PhotoAlbumSubType::SCREENSHOT:
        case PhotoAlbumSubType::CAMERA:
            validFetchColumns.insert(PhotoColumn::PHOTO_SUBTYPE);
            break;
        default:
            break;
    }
    for (const auto &column : fetchColumn) {
        if (column == PENDING_STATUS) {
            validFetchColumns.insert(MediaColumn::MEDIA_TIME_PENDING);
        } else if (isValidColumn(column)) {
            validFetchColumns.insert(column);
        } else if (column == MEDIA_DATA_DB_URI) {
            continue;
        } else if (DATE_TRANSITION_MAP.count(column) != 0) {
            validFetchColumns.insert(DATE_TRANSITION_MAP.at(column));
        } else {
            ANI_ERR_LOG("error");
            return false;
        }
    }
    fetchColumn.assign(validFetchColumns.begin(), validFetchColumns.end());

    return true;
}

static void UriAppendKeyValue(string &uri, const string &key, const string &value)
{
    string uriKey = key + '=';
    if (uri.find(uriKey) != string::npos) {
        return;
    }

    char queryMark = (uri.find('?') == string::npos) ? '?' : '&';
    string append = queryMark + key + '=' + value;

    size_t posJ = uri.find('#');
    if (posJ == string::npos) {
        uri += append;
    } else {
        uri.insert(posJ, append);
    }
}

bool MediaAniNativeImpl::PhotoAccessGetAssetsExecuteSync(std::shared_ptr<MediaLibraryAsyncContext> context,
    std::vector<std::unique_ptr<FileAsset>>& fileAssetArray)
{
    string queryUri = PAH_QUERY_PHOTO;
    UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));

    Uri uri(queryUri);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri, context->predicates,
        context->fetchColumn, errCode);
    if (resultSet == nullptr && !context->uri.empty() && errCode == E_PERMISSION_DENIED) {
        Uri queryWithUri(context->uri);
        resultSet = UserFileClient::Query(queryWithUri, context->predicates, context->fetchColumn, errCode);
    }
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet is nullptr");
        return false;
    }

    auto fetchResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    if (fetchResult == nullptr) {
        ANI_ERR_LOG("fetchResult is nullptr");
        return false;
    }
    fetchResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);

    auto file = fetchResult->GetFirstObject();
    while (file != nullptr) {
        fileAssetArray.push_back(move(file));
        file = fetchResult->GetNextObject();
    }
    return true;
}

bool MediaAniNativeImpl::PhotoAccessGetAssetsExecute(std::shared_ptr<MediaLibraryAsyncContext> context)
{
    string queryUri;
    if (context->uri == URI_ALL_DUPLICATE_ASSETS) {
        queryUri = PAH_ALL_DUPLICATE_ASSETS;
    } else if (context->uri == URI_OTHER_DUPLICATE_ASSETS) {
        queryUri = PAH_OTHER_DUPLICATE_ASSETS;
    } else {
        queryUri = PAH_QUERY_PHOTO;
    }
    UriAppendKeyValue(queryUri, API_VERSION, to_string(MEDIA_API_VERSION_V10));

    Uri uri(queryUri);
    int errCode = 0;
    shared_ptr<DataShare::DataShareResultSet> resultSet = UserFileClient::Query(uri, context->predicates,
        context->fetchColumn, errCode);
    if (resultSet == nullptr && !context->uri.empty() && errCode == E_PERMISSION_DENIED) {
        Uri queryWithUri(context->uri);
        resultSet = UserFileClient::Query(queryWithUri, context->predicates, context->fetchColumn, errCode);
    }
    if (resultSet == nullptr) {
        ANI_ERR_LOG("resultSet is nullptr");
        return false;
    }

    context->fetchFileResult = make_unique<FetchResult<FileAsset>>(move(resultSet));
    context->fetchFileResult->SetResultNapiType(ResultNapiType::TYPE_PHOTOACCESS_HELPER);
    return true;
}
} // namespace Media
} // namespace OHOS