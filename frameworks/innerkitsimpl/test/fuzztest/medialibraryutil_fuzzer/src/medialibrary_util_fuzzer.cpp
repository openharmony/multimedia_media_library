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
#include "medialibrary_util_fuzzer.h"

#include <cstdint>
#include <string>
#include <thread>

#include "ability_context_impl.h"
#include "app_mgr_interface.h"
#include "cloud_sync_utils.h"
#include "cpu_utils.h"
#include "medialibrary_album_operations.h"
#include "medialibrary_analysis_album_operations.h"
#include "medialibrary_app_uri_permission_operations.h"
#include "medialibrary_appstate_observer.h"
#include "media_log.h"
#include "medialibrary_command.h"
#include "medialibrary_dir_operations.h"
#include "medialibrary_uripermission_operations.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_data_manager_utils.h"
#include "multistages_capture_dfx_first_visit.h"
#include "rdb_predicates.h"
#include "datashare_values_bucket.h"
#include "media_analysis_proxy.h"
#include "media_analysis_helper.h"
#include "background_cloud_file_processor.h"
#include "medialibrary_db_const.h"
#include "medialibrary_album_refresh.h"
#include "scanner_utils.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore_manager.h"
#include "database_adapter.h"
#include "userfile_manager_types.h"
#include "medialibrary_operation.h"
#include "datashare_helper.h"

#define private public
#include "medialibrary_common_utils.h"
#include "permission_utils.h"
#include "photo_file_utils.h"
#undef private

namespace OHOS {
using namespace std;
const int32_t EVEN = 2;
const std::string PERMISSION = "testName";
const std::string ROOT_MEDIA_DIR = "/storage/cloud/files/";
const std::string PHOTO_PATH = "/Photo/5/IMG_1741264239_005.jpg";
const std::string DISPLAY_NAME = "IMG_20250306_202859.jpg";
const std::string FILE_HIDDEN = ".FileHidden/";
static const int32_t E_ERR = -1;
static const string PHOTOS_TABLE = "Photos";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline int64_t FuzzInt64(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return 0;
    }
    return static_cast<int64_t>(*data);
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
    return Uri(FuzzString(data, size));
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline Media::CpuAffinityType FuzzCpuAffinityType(const uint8_t *data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CpuAffinityType::CPU_IDX_0) &&
        value <= static_cast<int32_t>(Media::CpuAffinityType::CPU_IDX_11)) {
        return static_cast<Media::CpuAffinityType>(value);
    }
    return Media::CpuAffinityType::CPU_IDX_DEFAULT;
}

static inline Security::AccessToken::PermissionUsedType FuzzPermissionUsedType(const uint8_t *data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Security::AccessToken::PermissionUsedType::NORMAL_TYPE) &&
        value <= static_cast<int32_t>(Security::AccessToken::PermissionUsedType::PERM_USED_TYPE_BUTT)) {
        return static_cast<Security::AccessToken::PermissionUsedType>(value);
    }
    return Security::AccessToken::PermissionUsedType::INVALID_USED_TYPE;
}

static inline Media:MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return Media::MediaLibraryCommand(FuzzUri(data, size));
}

static int32_t InsertAsset(const uint8_t *data, size_t size, string photoId)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));
    values.PutString(Media::PhotoColumn::PHOTO_VISIT_TIME, FuzzString(data, size));
    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

void SetTables()
{
    vector<string> createTableSqlList = { Media::PhotoColumn::CREATE_PHOTO_TABLE };
    for (auto &createTableSql : createSqlList) {
        CHECK_AND_RETURN_LOG(g_rdbStore != nullptr, "g_rdbStore is null.");
        int32_t ret = g_rdbStore->ExecuteSql(createTableSql);
        if (ret != NativeRdb::E_OK) {
            MEDIA_ERR_LOG("Execute sql %{private}s failed.", createTableSql.c_str());
            return;
        }
        MEDIA_DEBUG_LOG("Execute sql %{private}s success.", createTableSql.c_str());
    }
}
static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    int32_t sceneCode = 0;
    auto ret = Media::MediaLibraryDataManager::GetInstance()->InitMediaLibraryMgr(abilityContextImpl, abilityContextImpl,
        sceneCode);
    CHECK_AND_RETURN_LOG(ret == NativeRdb::E_OK, "InitMediaLibrary Mgr failed, ret: %{public}d.", ret);
    auto rdbStore = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr.");
        return;
    }
    g_rdbStore = rdbStore;
    SetTables();
}

static void CommandTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 10;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    NativeRdb::ValuesBucket value;
    int32_t offset = 0;
    int32_t operationObject1 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType1 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi1 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject1),
        static_cast<Media::OperationType>(operationType1), static_cast<Media::MediaLibraryApi>(mediaLibraryApi1));
    cmd.SetTableName(FuzzString(data, size));
    cmd.SetBundleName(FuzzString(data, size));
    cmd.SetDeviceName(FuzzString(data, size));
    cmd.SetResult(FuzzString(data, size));
    offset += sizeof(int32_t);
    int32_t operationObject2 = FuzzInt32(data + offset, size);
    cmd.SetOprnObject(static_cast<Media::OperationObject>(operationObject2));
    cmd.GetOprnFileId();
    cmd.SetOprnAssetId(FuzzString(data, size));
    DataShare::DataSharePredicates pred;
    cmd.SetDataSharePred(pred);
    cmd.SetValueBucket(value);
    Media::MediaLibraryCommand cmdValueBucket(FuzzUri(data, size), value);
    offset += sizeof(int32_t);
    int32_t operationObject3 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType2 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi2 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmdValueBucket2(static_cast<Media::OperationObject>(operationObject3),
        static_cast<Media::OperationType>(operationType2), value,
        static_cast<Media::MediaLibraryApi>(mediaLibraryApi2));
    offset += sizeof(int32_t);
    int32_t operationObject4 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType3 = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi3 = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmdDevice(static_cast<Media::OperationObject>(operationObject4),
        static_cast<Media::OperationType>(operationType3), FuzzString(data, size),
        static_cast<Media::MediaLibraryApi>(mediaLibraryApi3));
}

static void DirOperationTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    Media::MediaLibraryDirOperations::HandleDirOperation(cmd);
    Media::MediaLibraryDirOperations::CreateDirOperation(cmd);
    Media::MediaLibraryDirOperations::TrashDirOperation(cmd);
}

static void UriPermissionTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 6;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    NativeRdb::ValuesBucket rdbValueBucket;
    offset += sizeof(int32_t);
    rdbValueBucket.Put(Media::PERMISSION_FILE_ID, FuzzInt32(data + offset, size));
    rdbValueBucket.Put(Media::PERMISSION_BUNDLE_NAME, FuzzString(data, size));
    rdbValueBucket.Put(Media::PERMISSION_MODE, "r");
    rdbValueBucket.Put(Media::PERMISSION_TABLE_TYPE, FuzzString(data, size));
    cmd.SetValueBucket(rdbValueBucket);
    Media::UriPermissionOperations::HandleUriPermOperations(cmd);
    Media::UriPermissionOperations::HandleUriPermInsert(cmd);
    offset += sizeof(int32_t);
    Media::UriPermissionOperations::InsertBundlePermission(FuzzInt32(data + offset, size), FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    Media::UriPermissionOperations::DeleteBundlePermission(FuzzString(data, size),
        FuzzString(data, size), FuzzString(data, size));
    string mode = "r";
    Media::UriPermissionOperations::CheckUriPermission(FuzzString(data, size), mode);

    offset += sizeof(int32_t);
    Media::UriPermissionOperations::GetUriPermissionMode(FuzzString(data, size), FuzzString(data, size),
        FuzzInt32(data + offset, size), mode);
    Media::UriPermissionOperations::UpdateOperation(cmd);
    Media::UriPermissionOperations::InsertOperation(cmd);
    std::vector<NativeRdb::ValuesBucket> rdbValues;
    Media::UriPermissionOperations::BatchInsertOperation(cmd, rdbValues);
    Media::UriPermissionOperations::DeleteOperation(cmd);
    std::vector<DataShare::DataShareValuesBucket> sharedValues;
    DataShare::DataShareValuesBucket valueTest1;
    valueTest1.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    valueTest1.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    DataShare::DataShareValuesBucket valueTest2;
    valueTest2.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    valueTest2.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    sharedValues.push_back(valueTest1);
    sharedValues.push_back(valueTest2);
    Media::UriPermissionOperations::GrantUriPermission(cmd, sharedValues);
    Media::UriPermissionOperations::DeleteAllTemporaryAsync();
}

static void AnalysisTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 7;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    std::vector<std::string> columns;
    NativeRdb::ValuesBucket values;
    DataShare::DataSharePredicates pred;
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    cmd.SetTableName("Photos");
    Media::MergeAlbumInfo info1;
    offset += sizeof(int32_t);
    info1.albumId = FuzzInt32(data + offset, size);
    Media::MergeAlbumInfo info2;
    offset += sizeof(int32_t);
    info2.albumId = FuzzInt32(data + offset, size);
    std::vector<Media::MergeAlbumInfo> infos;
    infos.push_back(info1);
    infos.push_back(info2);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateMergeGroupAlbumsInfo(infos);
    offset += sizeof(int32_t);
    Media::MediaLibraryAnalysisAlbumOperations::HandleGroupPhotoAlbum(
        static_cast<Media::OperationType>(FuzzInt32(data + offset, size)), values, pred);
    Media::MediaLibraryAnalysisAlbumOperations::QueryGroupPhotoAlbum(cmd, columns);
    offset += sizeof(int32_t);
    Media::MediaLibraryAnalysisAlbumOperations::UpdateGroupPhotoAlbumById(FuzzInt32(data + offset, size));
}

static void AppPermissionTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    std::vector<std::string> columns;
    NativeRdb::RdbPredicates rdbPred("Photos");
    DataShare::DataSharePredicates sharedPred;
    int32_t offset = 0;
    int32_t operationObject = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t operationType = FuzzInt32(data + offset, size);
    offset += sizeof(int32_t);
    int32_t mediaLibraryApi = FuzzInt32(data + offset, size);
    Media::MediaLibraryCommand cmd(static_cast<Media::OperationObject>(operationObject),
        static_cast<Media::OperationType>(operationType), static_cast<Media::MediaLibraryApi>(mediaLibraryApi));
    Media::MediaLibraryAppUriPermissionOperations::HandleInsertOperation(cmd);
    std::vector<DataShare::DataShareValuesBucket> sharedValues;
    DataShare::DataShareValuesBucket values;
    values.Put(Media::AppUriPermissionColumn::FILE_ID, "file_id");
    values.Put(Media::AppUriPermissionColumn::APP_ID, "appid");
    sharedValues.push_back(values);
    Media::MediaLibraryAppUriPermissionOperations::BatchInsert(cmd, sharedValues);
    Media::MediaLibraryAppUriPermissionOperations::DeleteOperation(rdbPred);
    Media::MediaLibraryAppUriPermissionOperations::QueryOperation(sharedPred, columns);
}

static void AppStateTest()
{
    Media::MedialibraryAppStateObserverManager::GetInstance().SubscribeAppState();
    Media::MedialibraryAppStateObserverManager::GetInstance().UnSubscribeAppState();
}

static void MediaLibraryManagerTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryDataManagerUtils::IsNumber(FuzzString(data, size));
    Media::MediaLibraryDataManagerUtils::GetOperationType(FuzzString(data, size));
    Media::MediaLibraryDataManagerUtils::GetDisPlayNameFromPath(FuzzString(data, size));
    std::vector<std::string> whereArgs;
    std::string str = FuzzString(data, size);
    Media::MediaLibraryDataManagerUtils::ObtionCondition(str, whereArgs);
    Media::MediaLibraryDataManagerUtils::GetTypeUriByUri(str);
}

static void MultiStagesAdapterTest(const uint8_t *data, size_t size)
{
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    Media::DatabaseAdapter::Update(cmd);
    MEDIA_INFO_LOG("MultiStagesAdapterTest");
}

static void MultistageTest(const uint8_t *data, size_t size)
{
    string photoId = FuzzString(data, size);
    int32_t fileId = InsertAsset(data, size, photoId);
    MEDIA_INFO_LOG("fileId: %{public}d.", fileId);
    Media::MultiStagesCaptureDfxFirstVisit::GetInstance().Report(FuzzString(data, size));
    MEDIA_INFO_LOG("MultistageTest");
}

static void RefreshAlbumTest()
{
    Media::RefreshAlbums(true);
}

static void ActiveAnalysisTest()
{
    std::vector<std::string> fileIds;
    fileIds.push_back("1");
    Media::MediaAnalysisHelper::StartMediaAnalysisServiceSync(
        static_cast<int32_t>(Media::MediaAnalysisProxy::ActivateServiceType::START_SERVICE_OCR), fileIds);
    Media::MediaAnalysisHelper::StartMediaAnalysisServiceAsync(
        static_cast<int32_t>(Media::MediaAnalysisProxy::ActivateServiceType::START_SERVICE_OCR), fileIds);
    Media::MediaAnalysisHelper::AsyncStartMediaAnalysisService(
        static_cast<int32_t>(Media::MediaAnalysisProxy::ActivateServiceType::START_SERVICE_OCR), fileIds);
    Media::MediaAnalysisHelper::StartPortraitCoverSelectionAsync(fileIds.at(0));
    (void)Media::MediaAnalysisHelper::ParseGeoInfo(fileIds, true);
}

static void CloudDownloadTest()
{
    Media::BackgroundCloudFileProcessor::StartTimer();
    int sleepTime = 200;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    Media::BackgroundCloudFileProcessor::StopTimer();
}

static void CpuUtilsTest(const uint8_t *data, size_t size)
{
    Media::CpuUtils::SlowDown();
    Media::CpuAffinityType cpuAffinityType = FuzzCpuAffinityType(data, size);
    Media::CpuUtils::SetSelfThreadAffinity(cpuAffinityType);
    Media::CpuUtils::ResetSelfThreadAffinity();
    Media::CpuUtils::ResetCpu();
}

static void CommonUtilsTest(const uint8_t *data, size_t size)
{
    std::string str = FuzzString(data, size);
    Media::MediaLibraryCommonUtils::CanConvertStrToInt32(str);
}

static void PermissionUtilsTest(const uint8_t *data, size_t size)
{
    int uid = FuzzInt32(data, size);
    std::string packageName = FuzzString(data, size);
    Media::PermissionUtils::UpdatePackageNameInCache(uid, packageName);

    std::string appId = FuzzString(data, size);
    int64_t tokenId = FuzzInt64(data, size);
    Media::PermissionUtils::GetMainTokenId(appId, tokenId);

    std::string permission = FuzzString(data, size);
    bool permGranted = FuzzBool(data, size);
    Security::AccessToken::PermissionUsedType type = FuzzPermissionUsedType(data, size);
    Media::PermissionUtils::CollectPermissionInfo(permission, permGranted, type, uid);

    vector<string> perms = FuzzVectorString(data, size);
    unsigned int tokenCaller = FuzzInt32(data, size);
    Media::PermissionUtils::CheckPhotoCallerPermission(perms, uid, tokenCaller);

    permission = FuzzBool(data, size) ? PERMISSION : FuzzString(data, size);
    Media::PermissionUtils::CheckPhotoCallerPermission(permission, tokenCaller);
    Media::PermissionUtils::SetEPolicy();
}

static void CloudSyncUtilsTest()
{
    Media::CloudSyncUtils::IsUnlimitedTrafficStatusOn();
    Media::CloudSyncUtils::IsCloudSyncSwitchOn();
    Media::CloudSyncUtils::IsCloudDataAgingPolicyOn();
}

static void PhotoFileUtilsTest(const uint8_t *data, size_t size)
{
    std::string photoPath = FuzzBool(data, size) ? ROOT_MEDIA_DIR : FuzzString(data, size);
    int32_t userId = FuzzInt32(data, size);
    Media::PhotoFileUtils::GetEditDataPath(photoPath, userId);
    Media::PhotoFileUtils::GetEditDataCameraPath(photoPath, userId);
    Media::PhotoFileUtils::GetEditDataSourcePath(photoPath, userId);

    int64_t editTime = FuzzInt64(data, size);
    Media::PhotoFileUtils::HasEditData(editTime);
    bool hasEditDataCamera = FuzzBool(data, size);
    int32_t effectMode = FuzzInt32(data, size);
    Media::PhotoFileUtils::HasSource(hasEditDataCamera, editTime, effectMode);

    photoPath = FuzzBool(data, size) ? "" : FuzzString(data, size);
    Media::PhotoFileUtils::GetMetaDataRealPath(photoPath, userId);
    photoPath = PHOTO_PATH;
    Media::PhotoFileUtils::GetMetaDataRealPath(photoPath, userId);

    photoPath = FuzzBool(data, size) ? ROOT_MEDIA_DIR : "";
    Media::PhotoFileUtils::IsThumbnailExists(photoPath);
    photoPath = FuzzString(data, size);
    Media::PhotoFileUtils::IsThumbnailExists(photoPath);
}

static void ScannerUtilsTest(const uint8_t *data, size_t size)
{
    std::string pathOrDisplayName = FuzzBool(data, size) ? DISPLAY_NAME : FuzzString(data, size);
    Media::ScannerUtils::GetFileExtension(pathOrDisplayName);

    std::string path = FuzzBool(data, size) ? "" : FuzzString(data, size);
    Media::ScannerUtils::IsDirectory(path);
    Media::ScannerUtils::IsRegularFile(path);

    path = FuzzBool(data, size) ? FILE_HIDDEN : FuzzString(data, size);
    Media::ScannerUtils::IsFileHidden(path);

    std::string dir = FuzzString(data, size);
    Media::ScannerUtils::GetRootMediaDir(dir);

    std::string displayName = FuzzString(data, size);
    Media::ScannerUtils::GetFileTitle(displayName);

    path = FuzzBool(data, size) ? FILE_HIDDEN : FuzzString(data, size);
    Media::ScannerUtils::IsDirHidden(path, true);

    path = FuzzBool(data, size) ? ROOT_MEDIA_DIR + "Pictures": FuzzString(data, size);
    Media::ScannerUtils::CheckSkipScanList(path);
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
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    OHOS::CommandTest(data, size);
    OHOS::DirOperationTest(data, size);
    OHOS::UriPermissionTest(data, size);
    OHOS::AnalysisTest(data, size);
    OHOS::AppPermissionTest(data, size);
    OHOS::AppStateTest();
    OHOS::MediaLibraryManagerTest(data, size);
    OHOS::MultiStageAdapterTest(data, size);
    OHOS::MultistageTest(data, size);
    OHOS::RefreshAlbumTest();
    OHOS::ActiveAnalysisTest();
    OHOS::CloudDownloadTest();
    OHOS::CpuUtilsTest(data, size);
    OHOS::CommonUtilsTest(data, size);
    OHOS::PermissionUtilsTest(data, size);
    OHOS::CloudSyncUtilsTest();
    OHOS::PhotoFileUtilsTest(data, size);
    OHOS::ScannerUtilsTest(data, size);
    return 0;
}
