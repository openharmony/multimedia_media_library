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
