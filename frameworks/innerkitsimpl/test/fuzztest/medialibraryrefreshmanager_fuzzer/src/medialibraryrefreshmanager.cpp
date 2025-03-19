/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "medialibraryrefreshmanager.h"

#include "albums_refresh_manager.h"
#include "ability_context_impl.h"
#include "medialibrary_errno.h"
#include "medialibrary_type_const.h"
#include "medialibrary_tracer.h"
#include "media_log.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "media_file_uri.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_rdb_transaction.h"
#include "medialibrary_notify.h"
#include "userfilemgr_uri.h"
#include "media_refresh_album_column.h"
#include "albums_refresh_worker.h"
#include "albums_refresh_notify.h"
#include "rdb_sql_utils.h"
#include "result_set_utils.h"
#include "photo_album_column.h"
#include "medialibrary_rdb_utils.h"
#include "vision_column.h"
#include "medialibrary_restore.h"
#include "post_event_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore.h"
#include "media_datashare_ext_ability.h"
#ifdef HAS_POWER_MANAGER_PART
#include "power_mgr_client.h"
#endif

namespace OHOS {
using namespace std;
using namespace DataShare;
using namespace Media;
using ChangeType = DataShare::DataShareObserver::ChangeType;

std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
const int32_t EVEN = 2;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int8_t FuzzInt8(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int8_t)) {
        return 0;
    }
    return static_cast<int8_t>(*data);
}

static inline int16_t FuzzInt16(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int16_t)) {
        return 0;
    }
    return static_cast<int16_t>(*data);
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % EVEN) == 0;
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::EXTENSION_FUZZER_URI_LISTS.size());
    if (*data < length) {
        return Uri(Media::EXTENSION_FUZZER_URI_LISTS[*data]);
    }
    return Uri("Undefined");
}

static inline std::list<Uri> FuzzListUri(const uint8_t* data, size_t size)
{
    std::list<Uri> uri = {FuzzUri(data, size)};
    return uri;
}

static inline std::vector<std::string> FuzzVector(const uint8_t* data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline std::unordered_set<std::string> FuzzUnorderedSet(const uint8_t* data, size_t size)
{
    std::unordered_set<std::string> orderset = {FuzzString(data, size)};
    return orderset;
}

static inline Media::NotifyType FuzzNotifyTypeCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::NotifyType::NOTIFY_ADD) &&
        value <= static_cast<int32_t>(Media::NotifyType::NOTIFY_INVALID)) {
        return static_cast<Media::NotifyType>(value);
    }
    return  Media::NotifyType::NOTIFY_ADD;
}

static inline ChangeType FuzzChangeType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(ChangeType::INSERT) &&
        value <= static_cast<int32_t>(ChangeType::OTHER)) {
        return static_cast<ChangeType>(value);
    }
    return  ChangeType::INSERT;
}

static inline Media::ForceRefreshType FuzzForceRefreshTypeCause(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::ForceRefreshType::NONE) &&
        value <= static_cast<int32_t>(Media::ForceRefreshType::EXCEPTION)) {
        return static_cast<Media::ForceRefreshType>(value);
    }
    return  Media::ForceRefreshType::NONE;
}

static inline Media::CloudSyncNotifyInfo FuzzCloudSyncNotifyInfo(const uint8_t* data, size_t size)
{
    Media::CloudSyncNotifyInfo info;
    const void* data_ = nullptr;
    ChangeType type = FuzzChangeType(data, size);
    info.uris = FuzzListUri(data, size);
    info.type = type;
    info.data = data_;
    return info;
}

static Media::SyncNotifyInfo FuzzSyncNotifyInfo(const uint8_t* data, size_t size)
{
    Media::SyncNotifyInfo info;
    info.taskType = FuzzInt16(data, size);
    info.syncType = FuzzInt16(data, size);
    info.notifyType = FuzzNotifyTypeCause(data, size);
    info.syncId = FuzzString(data, size);
    info.totalAssets = FuzzInt32(data, size);
    info.totalAlbums = FuzzInt32(data, size);
    info.uriType = FuzzInt8(data, size);
    info.reserve = FuzzInt8(data, size);
    info.urisSize  = FuzzInt16(data, size);
    info.uris = FuzzListUri(data, size);
    info.extraUris = FuzzListUri(data, size);
    info.uriIds = FuzzUnorderedSet(data, size);
    info.notifyAssets = FuzzBool(data, size);
    info.notifyAlbums = FuzzBool(data, size);
    info.refershResult = FuzzInt32(data, size);
    info.forceRefreshType = FuzzForceRefreshTypeCause(data, size);
    return info;
}

static void RefreshNotifyInfoTest(const uint8_t* data, size_t size)
{
    Media::SyncNotifyInfo fuzznotifyinfo = FuzzSyncNotifyInfo(data, size);
    Media::CloudSyncNotifyInfo fuzzsyncnotifyinfo = FuzzCloudSyncNotifyInfo(data, size);
    std::vector<std::string> fuzzvector = FuzzVector(data, size);
    Media::AlbumsRefreshManager &instance = Media::AlbumsRefreshManager::GetInstance();
    instance.RefreshPhotoAlbums(fuzznotifyinfo);
    instance.AddAlbumRefreshTask(fuzznotifyinfo);
    instance.NotifyPhotoAlbums(fuzznotifyinfo);
    instance.HasRefreshingSystemAlbums();
    instance.GetSyncNotifyInfo(fuzzsyncnotifyinfo, FuzzInt8(data, size));
    instance.CovertCloudId2AlbumId(g_rdbStore, fuzzvector);
    instance.CovertCloudId2FileId(g_rdbStore, fuzzvector);
    instance.RefreshPhotoAlbumsBySyncNotifyInfo(g_rdbStore, fuzznotifyinfo);
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createTableSqlList) {
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success", createTableSql.c_str());
    }
}

static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl,
        abilityContextImpl, sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibraryMgr failed, ret: %{public}d", ret);

    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::RefreshNotifyInfoTest(data, size);
    return 0;
}