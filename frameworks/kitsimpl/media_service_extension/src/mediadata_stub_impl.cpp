/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "mediadata_stub_impl.h"
#include "abs_rdb_predicates.h"
#include "data_ability_predicates.h"
#include "device_manager.h"
#include "device_manager_callback.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_smartalbum_map_operations.h"
#include "medialibrary_smartalbum_operations.h"
#include "medialibrary_device.h"
#include "medialibrary_device_info.h"
#include "medialibrary_file_operations.h"
#include "medialibrary_kvstore_operations.h"
#include "result_set.h"
#include "hilog_wrapper.h"
#include "medialibrary_data_manager.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::NativeRdb;
using namespace OHOS::DistributedKv;
using namespace OHOS::Media;

namespace OHOS {
namespace AppExecFwk {
std::vector<std::string> MediaDataStubImpl::GetFileTypes(const Uri &uri, const std::string &mimeTypeFilter)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::string> ret;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::OpenFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = -1;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::OpenRawFile(const Uri &uri, const std::string &mode)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = -1;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Insert(const Uri &uri, const NativeRdb::ValuesBucket &value)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Update(const Uri &uri, const NativeRdb::ValuesBucket &value,
    const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::Delete(const Uri &uri, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int32_t MediaDataStubImpl::InitMediaLibraryRdbStore()
{
    HILOG_INFO("InitMediaLibraryRdbStore IN |Rdb Verison %{private}d", MEDIA_RDB_VERSION);
    MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(context_);
    /*
    if (isRdbStoreInitialized) {
        return 0;
    }

    int32_t errCode = 0;
    string databaseDir = context_->GetDatabaseDir() + "/" + MEDIA_DATA_ABILITY_DB_NAME;
    RdbStoreConfig config(databaseDir);
    config.SetBundleName("com.example.myapplicaion");
    config.SetName(MEDIA_DATA_ABILITY_DB_NAME);
    MediaLibraryDataCallBack rdbDataCallBack;

    rdbStore_ = RdbHelper::GetRdbStore(config, MEDIA_RDB_VERSION, rdbDataCallBack, errCode);
    if (rdbStore_ == nullptr) {
        HILOG_ERROR("InitMediaRdbStore GetRdbStore is failed ");
        return errCode;
    }
    sRdbStoreInitialized = true;
    */

    return 0;
}

std::shared_ptr<NativeRdb::AbsSharedResultSet> MediaDataStubImpl::Query(const Uri &uri,
    std::vector<std::string> &columns, const NativeRdb::DataAbilityPredicates &predicates)
{
    HILOG_INFO("MediaDataStubImpl::%{public}s begin.", __func__);
    shared_ptr<AbsSharedResultSet> queryResultSet;
    /*
    TableType tabletype = TYPE_ALBUM_TABLE;
    string strRow, uriString = uri.ToString();
    if (tabletype == TYPE_SMARTALBUM || tabletype == TYPE_SMARTALBUM_MAP) {
        HILOG_INFO("MediaDataStubImpl::%{public}s smartalbum.", __func__);
    } else if (tabletype == TYPE_ASSETSMAP_TABLE || tabletype == TYPE_SMARTALBUMASSETS_TABLE) {
        HILOG_INFO("MediaDataStubImpl::%{public}s assetmap.", __func__);
    } else if (tabletype == TYPE_ALL_DEVICE || tabletype == TYPE_ACTIVE_DEVICE) {
        HILOG_INFO("MediaDataStubImpl::%{public}s device", __func__);
    } else if (tabletype == TYPE_ALBUM_TABLE) {
        HILOG_INFO("MediaDataStubImpl::%{public}s album.", __func__);
            queryResultSet = rdbStore_->QuerySql("SELECT * FROM " + ABLUM_VIEW_NAME);
    } else {
    }
    */
    queryResultSet =  MediaLibraryDataManager::GetInstance()->Query(uri, columns, predicates);

    HILOG_INFO("MediaDataStubImpl::%{public}s end.", __func__);
    return queryResultSet;
}

std::string MediaDataStubImpl::GetType(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::string ret = "";
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

int MediaDataStubImpl::BatchInsert(const Uri &uri, const std::vector<NativeRdb::ValuesBucket> &values)
{
    HILOG_INFO("%{public}s begin.", __func__);
    int ret = 0;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &dataObserver)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

bool MediaDataStubImpl::NotifyChange(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    bool ret = false;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return ret;
}

Uri MediaDataStubImpl::NormalizeUri(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    Uri urivalue("");
    HILOG_INFO("%{public}s end successfully.", __func__);
    return urivalue;
}

Uri MediaDataStubImpl::DenormalizeUri(const Uri &uri)
{
    HILOG_INFO("%{public}s begin.", __func__);
    Uri urivalue("");
    HILOG_INFO("%{public}s end successfully.", __func__);
    return urivalue;
}

std::vector<std::shared_ptr<AppExecFwk::DataAbilityResult>> MediaDataStubImpl::ExecuteBatch(
    const std::vector<std::shared_ptr<AppExecFwk::DataAbilityOperation>> &operations)
{
    HILOG_INFO("%{public}s begin.", __func__);
    std::vector<std::shared_ptr<DataAbilityResult>> results;
    HILOG_INFO("%{public}s end successfully.", __func__);
    return results;
}
} // namespace AppExecFwk
} // namespace OHOS
