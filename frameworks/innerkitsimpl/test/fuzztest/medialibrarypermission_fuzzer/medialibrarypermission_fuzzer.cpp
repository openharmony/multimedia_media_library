/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "medialibrarypermission_fuzzer.h"

#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_context_impl.h"
#include "media_log.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_errno.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_kvstore_manager.h"
#include "media_app_uri_permission_column.h"
#include "media_composite_permission_check.h"
#include "media_read_permission_check.h"
#include "media_write_permission_check.h"

namespace OHOS {
namespace Media {
using namespace std;
static const int32_t NUM_BYTES = 1;
static const int32_t DEFAULT_CALLING_UID = 1;
static const int32_t DEFAULT_BUSINESS_CODE = 1;
static const int32_t USER_ID = -1;
static const int32_t MAX_URI_TYPE = 1;
static const int32_t MAX_PERMISSION_TYPE = 5;
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider;

static const string SQL_INSERT_URIPERMISSION =
    "INSERT INTO UriPermission (target_tokenId, file_id, uri_type, permission_type)";
static const string VALUES_END = ") ";

bool MockIsCalledBySelf()
{
    return provider->ConsumeBool();
}

pid_t MockGetCallingUid()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, CALLING_UID_LIST.size() - DEFAULT_CALLING_UID);
    return CALLING_UID_LIST[data];
}

static int FuzzUriType()
{
    vector<int> vecUriType;
    vecUriType.assign(Media::AppUriPermissionColumn::URI_TYPES_ALL.begin(),
        Media::AppUriPermissionColumn::URI_TYPES_ALL.end());
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_URI_TYPE);
    return vecUriType[data];
}

static inline MediaLibraryBusinessCode FuzzMediaLibraryBusinessCode()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, BUSINESS_CODE_LIST.size() - DEFAULT_BUSINESS_CODE);
    return static_cast<MediaLibraryBusinessCode>(data);
}

static int FuzzPermissionType()
{
    vector<int> vecPermissionType;
    vecPermissionType.assign(AppUriPermissionColumn::PERMISSION_TYPES_ALL.begin(),
        AppUriPermissionColumn::PERMISSION_TYPES_ALL.end());
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_PERMISSION_TYPE);
    return vecPermissionType[data];
}

static void InsertUriPermissionRecord(
    const uint32_t &tokenId, const int32_t &fileId, const int32_t &uriType, const int32_t &permissionType)
{
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("g_rdbStore is null.");
        return;
    }
    std::string insertSql = SQL_INSERT_URIPERMISSION + " VALUES (" + to_string(tokenId) + "," + to_string(fileId) +
                            "," + to_string(uriType) + "," + to_string(permissionType) + VALUES_END;
    int32_t ret = g_rdbStore->ExecuteSql(insertSql);
    if (ret != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Execute sql %{public}s failed", insertSql.c_str());
        return;
    }
    MEDIA_INFO_LOG("Execute sql %{public}s success", insertSql.c_str());
}

static std::unordered_map<uint32_t, std::vector<std::vector<PermissionType>>> testMap = {
    {1, {{PRIVATE_PERM}}},
    {2, {{CLOUDFILE_SYNC}}},
    {3, {{READ_PERM}}},
    {4, {{WRITE_PERM}}},
    {5, {{SYSTEMAPI_PERM}, {}}},
    {6, {{}, {SYSTEMAPI_PERM}}},
    {7, {}},
    {8, {{PRIVATE_PERM, CLOUDFILE_SYNC, READ_PERM, WRITE_PERM}}},
    {9, {{CLOUD_READ}, {CLOUD_WRITE}}},
    {0, {{READ_PERM}, {WRITE_PERM}}},
    {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN), {{READ_PERM, WRITE_PERM}}},  // openfile api
};

static int32_t GetTestPermissionPolicy(uint32_t code, std::vector<std::vector<PermissionType>> &permissionPolicy)
{
    auto it = testMap.find(code);
    if (it != testMap.end()) {
        permissionPolicy = it->second;
        return E_SUCCESS;
    }
    return E_FAIL;
}

static int32_t PreparePermissionParam(uint32_t code, int32_t userId, bool isDBBypass,
    std::unordered_map<std::string, std::string> &headerMap, PermissionHeaderReq &data)
{
    std::vector<std::vector<PermissionType>> permissionPolicy;
    if (GetTestPermissionPolicy(code, permissionPolicy) != E_SUCCESS) {
        return E_FAIL;
    }
    data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, userId, permissionPolicy, isDBBypass);
    return E_SUCCESS;
}

static void ReadPermissionCheckTest()
{
    MEDIA_INFO_LOG("ReadPermissionCheckTest enter");
    uint32_t businessCode = static_cast<uint32_t>(FuzzMediaLibraryBusinessCode());

    uint32_t tokenId = PermissionUtils::GetTokenId();
    int32_t permissionType = static_cast<int32_t>(FuzzPermissionType());
    int32_t fileId = provider->ConsumeIntegral<int32_t>();
    int32_t uriType = static_cast<int32_t>(FuzzUriType());
    InsertUriPermissionRecord(tokenId, fileId, uriType, permissionType);
    PermissionHeaderReq data;
    std::unordered_map<std::string, std::string> headerMap;
    if (provider->ConsumeBool()) {
        headerMap = {
            {PermissionHeaderReq::FILE_ID_KEY, to_string(fileId)},
            {PermissionHeaderReq::URI_TYPE_KEY, to_string(uriType)},
            {PermissionHeaderReq::OPEN_URI_KEY, provider->ConsumeBytesAsString(NUM_BYTES)},
            {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
        };
    }
    int32_t userId = provider->ConsumeBool() ? USER_ID : provider->ConsumeIntegral<int32_t>();
    PreparePermissionParam(businessCode, userId, provider->ConsumeBool(), headerMap, data);

    auto readCompositePermCheck = make_shared<ReadCompositePermCheck>();
    CHECK_AND_RETURN_LOG(readCompositePermCheck != nullptr, "readCompositePermCheck is nullptr");
    shared_ptr<PermissionCheck> check = make_shared<CompositePermissionCheck>();
    readCompositePermCheck->AddCheck(check);
    readCompositePermCheck->CheckPermission(businessCode, data);

    auto readPrivilegePermCheck = make_shared<ReadPrivilegePermCheck>();
    CHECK_AND_RETURN_LOG(readPrivilegePermCheck != nullptr, "readPrivilegePermCheck is nullptr");
    readPrivilegePermCheck->CheckPermission(businessCode, data);

    auto dbReadPermCheck = make_shared<DbReadPermCheck>();
    CHECK_AND_RETURN_LOG(dbReadPermCheck != nullptr, "dbReadPermCheck is nullptr");
    dbReadPermCheck->CheckPermission(businessCode, data);

    auto grantReadPermCheck = make_shared<GrantReadPermCheck>();
    CHECK_AND_RETURN_LOG(grantReadPermCheck != nullptr, "grantReadPermCheck is nullptr");
    grantReadPermCheck->CheckPermission(businessCode, data);

    auto mediaToolReadPermCheck = make_shared<MediaToolReadPermCheck>();
    CHECK_AND_RETURN_LOG(mediaToolReadPermCheck != nullptr, "mediaToolReadPermCheck is nullptr");
    mediaToolReadPermCheck->CheckPermission(businessCode, data);

    auto deprecatedReadPermCheck = make_shared<DeprecatedReadPermCheck>();
    CHECK_AND_RETURN_LOG(deprecatedReadPermCheck != nullptr, "deprecatedReadPermCheck is nullptr");
    deprecatedReadPermCheck->CheckPermission(businessCode, data);
    MEDIA_INFO_LOG("ReadPermissionCheckTest end");
}

static void WritePermissionCheckTest()
{
    MEDIA_INFO_LOG("WritePermissionCheckTest enter");
    uint32_t businessCode = static_cast<uint32_t>(FuzzMediaLibraryBusinessCode());

    uint32_t tokenId = PermissionUtils::GetTokenId();
    int32_t permissionType = static_cast<int32_t>(FuzzPermissionType());
    int32_t fileId = provider->ConsumeIntegral<int32_t>();
    int32_t uriType = static_cast<int32_t>(FuzzUriType());
    InsertUriPermissionRecord(tokenId, fileId, uriType, permissionType);
    PermissionHeaderReq data;
    std::unordered_map<std::string, std::string> headerMap;
    if (provider->ConsumeBool()) {
        headerMap = {
            {PermissionHeaderReq::FILE_ID_KEY, to_string(fileId)},
            {PermissionHeaderReq::URI_TYPE_KEY, to_string(uriType)},
            {PermissionHeaderReq::OPEN_URI_KEY, provider->ConsumeBytesAsString(NUM_BYTES)},
            {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
        };
    }
    int32_t userId = provider->ConsumeBool() ? USER_ID : provider->ConsumeIntegral<int32_t>();
    PreparePermissionParam(businessCode, userId, provider->ConsumeBool(), headerMap, data);

    auto writeCompositePermCheck = make_shared<WriteCompositePermCheck>();
    CHECK_AND_RETURN_LOG(writeCompositePermCheck != nullptr, "writeCompositePermCheck is nullptr");
    shared_ptr<PermissionCheck> check = make_shared<CompositePermissionCheck>();
    writeCompositePermCheck->AddCheck(check);
    writeCompositePermCheck->CheckPermission(businessCode, data);

    auto writePrivilegePermCheck = make_shared<WritePrivilegePermCheck>();
    CHECK_AND_RETURN_LOG(writePrivilegePermCheck != nullptr, "writePrivilegePermCheck is nullptr");
    writePrivilegePermCheck->CheckPermission(businessCode, data);

    auto dbWritePermCheck = make_shared<DbWritePermCheck>();
    CHECK_AND_RETURN_LOG(dbWritePermCheck != nullptr, "dbWritePermCheck is nullptr");
    dbWritePermCheck->CheckPermission(businessCode, data);

    auto grantWritePermCheck = make_shared<GrantWritePermCheck>();
    CHECK_AND_RETURN_LOG(grantWritePermCheck != nullptr, "grantWritePermCheck is nullptr");
    grantWritePermCheck->CheckPermission(businessCode, data);

    auto mediaToolWritePermCheck = make_shared<MediaToolWritePermCheck>();
    CHECK_AND_RETURN_LOG(mediaToolWritePermCheck != nullptr, "mediaToolWritePermCheck is nullptr");
    mediaToolWritePermCheck->CheckPermission(businessCode, data);

    auto securityComponentPermCheck = make_shared<SecurityComponentPermCheck>();
    CHECK_AND_RETURN_LOG(securityComponentPermCheck != nullptr, "securityComponentPermCheck is nullptr");
    securityComponentPermCheck->CheckPermission(businessCode, data);

    auto deprecatedWritePermCheck = make_shared<DeprecatedWritePermCheck>();
    CHECK_AND_RETURN_LOG(deprecatedWritePermCheck != nullptr, "deprecatedWritePermCheck is nullptr");
    deprecatedWritePermCheck->CheckPermission(businessCode, data);

    auto shortTermWritePermCheck = make_shared<ShortTermWritePermCheck>();
    CHECK_AND_RETURN_LOG(shortTermWritePermCheck != nullptr, "shortTermWritePermCheck is nullptr");
    shortTermWritePermCheck->CheckPermission(businessCode, data);
    MEDIA_INFO_LOG("WritePermissionCheckTest end");
}

void SetTables()
{
    vector<string> createTableSqlList = {
        AppUriPermissionColumn::CREATE_APP_URI_PERMISSION_TABLE
    };
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

static inline void ClearKvStore()
{
    Media::MediaLibraryKvStoreManager::GetInstance().CloseAllKvStore();
}
} //namespace Media
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::Media::Init();
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::Media::provider = &provider;
    if (data == nullptr) {
        return 0;
    }
    OHOS::Media::isCalledBySelfPtr = OHOS::Media::MockIsCalledBySelf;
    OHOS::Media::getCallingUidPtr = OHOS::Media::MockGetCallingUid;
    OHOS::Media::ReadPermissionCheckTest();
    OHOS::Media::WritePermissionCheckTest();
    OHOS::Media::ClearKvStore();
    return 0;
}