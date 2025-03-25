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

#include "medialibraryenhancement_fuzzer.h"

#include <cstdint>
#include <string>

#include "ability_context_impl.h"
#include "data_ability_observer_interface.h"
#include "datashare_business_error.h"
#include "datashare_helper.h"
#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "medialibrary_command.h"
#include "media_datashare_ext_ability.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_unistore.h"
#include "medialibrary_unistore_manager.h"
#include "media_file_ext_ability.h"
#include "medialibrary_photo_operations.h"
#include "result_set_utils.h"
#include "medialibrary_rdb_utils.h"

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#define private public
#define protected public
#include "file_utils.h"
#include "enhancement_manager.h"
#include "enhancement_service_callback.h"
#include "enhancement_task_manager.h"
#include "enhancement_service_adapter.h"
#include "enhancement_database_operations.h"
#undef private
#undef protected
#endif

#include "media_datashare_stub_impl.h"
#include "media_file_utils.h"
#include "media_log.h"
#include "runtime.h"

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
using namespace DataShare;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static const string TESTING_DISPLAYNAME = "IMG_20240904_133901.jpg";
static const int32_t isEven = 2;
static const int32_t NO = 0;
static const int32_t YES = 1;
static const int32_t E_ERR = -1;
static const string PHOTOS_TABLE = "Photos";
static const string PHOTO_URI_PREFIX = "file://media/Photo/";
static const string PHOTO_URI_PREFIX_UNDEDINED = "undedined/";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;

static inline int32_t FuzzInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return 0;
    }
    return static_cast<int32_t>(*data);
}

static inline uint32_t FuzzUInt32(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return 0;
    }
    return static_cast<uint32_t>(*data);
}

static inline bool FuzzBool(const uint8_t* data, size_t size)
{
    if (size == 0) {
        return false;
    }
    return (data[0] % isEven) == 0;
}

static inline string FuzzString(const uint8_t *data, size_t size)
{
    return {reinterpret_cast<const char*>(data), size};
}

static inline vector<string> FuzzVectorString(const uint8_t *data, size_t size)
{
    return {FuzzString(data, size)};
}

static inline Uri FuzzUriWithKeyValue(const uint8_t *data, size_t size, string uriStr)
{
    if (FuzzBool(data, size)) {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, Media::MEDIA_OPERN_KEYWORD, "true");
    } else {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, Media::MEDIA_OPERN_KEYWORD, "false");
    }
    Uri addTask(uriStr);
    return addTask;
}

static inline Uri FuzzUri(const uint8_t *data, size_t size)
{
    uint8_t length = static_cast<uint8_t>(Media::ENHANCEMENT_FUZZER_URI_LISTS.size());
    if (*data < length) {
        string uriStr = Media::ENHANCEMENT_FUZZER_URI_LISTS[*data];
        return FuzzUriWithKeyValue(data, size, uriStr);
    }
    return Uri("Undefined");
}

static inline Media::MediaLibraryCommand FuzzMediaLibraryCmd(const uint8_t *data, size_t size)
{
    return Media::MediaLibraryCommand(FuzzUri(data, size));
}

static inline Media::CloudEnhancementAvailableType FuzzCloudEnhancementAvailableType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CloudEnhancementAvailableType::NOT_SUPPORT) &&
        value <= static_cast<int32_t>(Media::CloudEnhancementAvailableType::TRASH)) {
        return static_cast<Media::CloudEnhancementAvailableType>(value);
    }
    return Media::CloudEnhancementAvailableType::PROCESSING_MANUAL;
}

static inline void FuzzMimeTypeAndDisplayNameExtension(const uint8_t *data, size_t size, string &mimeType,
    string &displayName)
{
    uint8_t length = static_cast<uint8_t>(Media::DISPLAY_NAME_EXTENSION_FUZZER_LISTS.size());
    if (*data < length) {
        mimeType = Media::MIMETYPE_FUZZER_LISTS[*data];
        displayName = FuzzString(data, size) + Media::DISPLAY_NAME_EXTENSION_FUZZER_LISTS[*data];
    }
}

static inline int32_t FuzzDynamicRangeType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::DynamicRangeType::SDR) &&
        value <= static_cast<int32_t>(Media::DynamicRangeType::HDR)) {
        return value;
    }
    return static_cast<int32_t>(Media::DynamicRangeType::SDR);
}

static inline int32_t FuzzPhotoSubType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::PhotoSubType::DEFAULT) &&
        value <= static_cast<int32_t>(Media::PhotoSubType::SUBTYPE_END)) {
        return value;
    }
    return static_cast<int32_t>(Media::PhotoSubType::CAMERA);
}

static inline int32_t FuzzCEErrorCodeType(const uint8_t* data, size_t size)
{
    int32_t value = FuzzInt32(data, size);
    if (value >= static_cast<int32_t>(Media::CEErrorCodeType::LIMIT_USAGE) &&
        value <= static_cast<int32_t>(Media::CEErrorCodeType::TASK_CANNOT_EXECUTE)) {
        return value;
    }
    return static_cast<int32_t>(Media::CEErrorCodeType::NON_RECOVERABLE);
}

static int32_t CreatePhotoApi10(int mediaType, const string &displayName)
{
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::CREATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket values;
    values.PutString(Media::MediaColumn::MEDIA_NAME, displayName);
    values.PutInt(Media::MediaColumn::MEDIA_TYPE, mediaType);
    cmd.SetValueBucket(values);
    int32_t ret = Media::MediaLibraryPhotoOperations::Create(cmd);
    if (ret < 0) {
        MEDIA_ERR_LOG("Create Photo failed, errCode=%{public}d", ret);
        return ret;
    }
    return ret;
}

string GetFilePath(int fileId)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return "";
    }

    vector<string> columns = { Media::PhotoColumn::MEDIA_FILE_PATH };
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::QUERY,
        Media::MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(Media::PhotoColumn::MEDIA_ID, to_string(fileId));
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return "";
    }
    auto resultSet = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->Query(cmd, columns);
    if (resultSet == nullptr || resultSet->GoToFirstRow() != NativeRdb::E_OK) {
        MEDIA_ERR_LOG("Can not get file Path");
        return "";
    }
    string path = Media::GetStringVal(Media::PhotoColumn::MEDIA_FILE_PATH, resultSet);
    return path;
}

int32_t MakePhotoUnpending(int fileId, bool isRefresh)
{
    if (fileId < 0) {
        MEDIA_ERR_LOG("this file id %{private}d is invalid", fileId);
        return Media::E_INVALID_FILEID;
    }

    string path = GetFilePath(fileId);
    if (path.empty()) {
        MEDIA_ERR_LOG("Get path failed");
        return Media::E_INVALID_VALUES;
    }
    int32_t errCode = Media::MediaFileUtils::CreateAsset(path);
    if (errCode != E_OK) {
        MEDIA_ERR_LOG("Can not create asset");
        return errCode;
    }

    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("can not get rdbstore");
        return Media::E_HAS_DB_ERROR;
    }
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::UPDATE);
    NativeRdb::ValuesBucket values;
    values.PutLong(Media::PhotoColumn::MEDIA_TIME_PENDING, 0);
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(Media::PhotoColumn::MEDIA_ID, to_string(fileId));
    int32_t changedRows = -1;
    errCode = Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore()->Update(cmd, changedRows);
    if (errCode != E_OK || changedRows <= 0) {
        MEDIA_ERR_LOG("Update pending failed, errCode = %{public}d, changeRows = %{public}d",
            errCode, changedRows);
        return errCode;
    }

    if (isRefresh) {
        Media::MediaLibraryRdbUtils::UpdateSystemAlbumInternal(
            Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore());
        Media::MediaLibraryRdbUtils::UpdateUserAlbumInternal(
            Media::MediaLibraryUnistoreManager::GetInstance().GetRdbStore());
    }
    return E_OK;
}

int32_t SetDefaultPhotoApi10(int mediaType, const std::string &displayName, bool isFresh = true)
{
    int fileId = CreatePhotoApi10(mediaType, displayName);
    if (fileId < 0) {
        MEDIA_ERR_LOG("create photo failed, res=%{public}d", fileId);
        return fileId;
    }
    int32_t errCode = MakePhotoUnpending(fileId, isFresh);
    if (errCode != E_OK) {
        return errCode;
    }
    return fileId;
}

int32_t PrepareHighQualityPhoto(const string &photoId, const string &displayName)
{
    auto fileId = SetDefaultPhotoApi10(Media::MediaType::MEDIA_TYPE_IMAGE, displayName);
    // update multi-stages capture db info
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::UPDATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket values;
    values.Put(Media::PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(Media::MultiStagesPhotoQuality::FULL));
    values.Put(Media::PhotoColumn::PHOTO_CE_AVAILABLE,
        static_cast<int32_t>(Media::CloudEnhancementAvailableType::PROCESSING_AUTO));
    values.Put(Media::PhotoColumn::PHOTO_ID, photoId);
    values.Put(Media::PhotoColumn::PHOTO_DEFERRED_PROC_TYPE, 1);
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(Media::MediaColumn::MEDIA_ID, to_string(fileId));
    Media::MediaLibraryPhotoOperations::Update(cmd);

    return fileId;
}

int32_t UpdateCEAvailable(int32_t fileId, int32_t ceAvailable, bool hasCloudWaterMark = false)
{
    // update cloud enhancement ce_available
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO,
        Media::OperationType::UPDATE, Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket values;
    values.Put(Media::PhotoColumn::PHOTO_CE_AVAILABLE, ceAvailable);
    if (hasCloudWaterMark) {
        values.Put(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, 1);
    }
    cmd.SetValueBucket(values);
    cmd.GetAbsRdbPredicates()->EqualTo(Media::MediaColumn::MEDIA_ID, to_string(fileId));
    return Media::MediaLibraryPhotoOperations::Update(cmd);
}

static int32_t InsertAsset(const uint8_t *data, size_t size, string photoId)
{
    if (g_rdbStore == nullptr) {
        return E_ERR;
    }
    NativeRdb::ValuesBucket values;
    values.PutString(Media::PhotoColumn::PHOTO_ID, photoId);
    values.PutString(Media::MediaColumn::MEDIA_FILE_PATH, FuzzString(data, size));

    string mimeType = "undefined";
    string displayName = ".undefined";
    FuzzMimeTypeAndDisplayNameExtension(data, size, mimeType, displayName);
    values.PutString(Media::MediaColumn::MEDIA_NAME, displayName);
    values.PutString(Media::MediaColumn::MEDIA_MIME_TYPE, mimeType);
    int32_t hidden = FuzzBool(data, size) ? YES : NO;
    values.PutInt(Media::MediaColumn::MEDIA_HIDDEN, hidden);
    values.PutInt(Media::PhotoColumn::PHOTO_SUBTYPE, FuzzPhotoSubType(data, size));
    values.PutInt(Media::PhotoColumn::PHOTO_DYNAMIC_RANGE_TYPE, FuzzDynamicRangeType(data, size));
    int32_t hasCloudWatermark = FuzzBool(data, size) ? YES : NO;
    values.PutInt(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, hasCloudWatermark);
    values.PutInt(Media::PhotoColumn::PHOTO_CE_AVAILABLE,
        static_cast<int32_t>(FuzzCloudEnhancementAvailableType(data, size)));

    int64_t fileId = 0;
    g_rdbStore->Insert(fileId, PHOTOS_TABLE, values);
    return static_cast<int32_t>(fileId);
}

static MediaEnhance::MediaEnhanceBundleHandle* FuzzMediaEnhanceBundle(const uint8_t* data, size_t size, string photoId)
{
    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    Media::EnhancementManager::GetInstance().enhancementService_->PutInt(mediaEnhanceBundle,
        MediaEnhance::MediaEnhance_Bundle_Key::ERROR_CODE, FuzzCEErrorCodeType(data, size));
    return mediaEnhanceBundle;
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
#endif

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
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

static void EnhancementManagerTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t fileId = InsertAsset(data, size, FuzzString(data, size));
    Media::EnhancementManager::GetInstance().Init();
    vector<string> fileIds = { to_string(fileId) };
    vector<string> photoIds;
    Media::EnhancementManager::GetInstance().CancelTasksInternal(fileIds, photoIds,
        FuzzCloudEnhancementAvailableType(data, size));
    Media::EnhancementManager::GetInstance().RemoveTasksInternal(fileIds, photoIds);
    int32_t offset = 0;
    Media::EnhancementManager::GetInstance().RevertEditUpdateInternal(FuzzInt32(data + offset, size));
    Media::EnhancementManager::GetInstance().RecoverTrashUpdateInternal(fileIds);

    DataSharePredicates predicates;
    string prefix = FuzzBool(data, size) ? PHOTO_URI_PREFIX : PHOTO_URI_PREFIX_UNDEDINED;
    string photoUri = prefix + "1/IMG_1722329102_000/" + TESTING_DISPLAYNAME;
    predicates.EqualTo(Media::MediaColumn::MEDIA_ID, photoUri);
    int32_t hasCloudWatermark = FuzzBool(data, size) ? YES : NO;
    predicates.EqualTo(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, hasCloudWatermark);
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd(data, size);
    cmd.SetDataSharePred(predicates);
    Media::EnhancementManager::GetInstance().HandleEnhancementUpdateOperation(cmd);
    vector<string> columns = FuzzVectorString(data, size);
    Media::EnhancementManager::GetInstance().HandleEnhancementQueryOperation(cmd, columns);

    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    offset += sizeof(int32_t);
    Media::EnhancementManager::GetInstance().AddServiceTask(mediaEnhanceBundle, FuzzInt32(data + offset, size),
        FuzzString(data, size), FuzzBool(data, size));
}

static void EnhancementManagerExtraTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 2;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    string photoId = FuzzString(data, size);
    int32_t testFileId = PrepareHighQualityPhoto(photoId, FuzzString(data, size));
    UpdateCEAvailable(testFileId, FuzzInt32(data, size));
    vector<string> testFileIds;
    testFileIds.push_back(to_string(testFileId));
    testFileIds.push_back("-1");
    vector<string> testphotoIds;

    Media::CloudEnhancementAvailableType cloudEnhancementAvailableType = Media::CloudEnhancementAvailableType::TRASH;
    if (FuzzBool(data, size)) {
        cloudEnhancementAvailableType = Media::CloudEnhancementAvailableType::EDIT;
    }
    Media::EnhancementManager::GetInstance().CancelTasksInternal(testFileIds, testphotoIds,
        cloudEnhancementAvailableType);
    NativeRdb::RdbPredicates servicePredicates(FuzzString(data, size));
    Media::EnhancementManager::GetInstance().GenerateAddAutoServicePredicates(servicePredicates);
    Media::EnhancementManager::GetInstance().GenerateCancelOperationPredicates(FuzzInt32(data, size),
        servicePredicates);
    Media::EnhancementManager::GetInstance().AddAutoServiceTask(mediaEnhanceBundle, FuzzInt32(data, size),
        FuzzString(data, size));
    Media::EnhancementManager::GetInstance().HandleCancelAllAutoOperation();
    Media::EnhancementManager::GetInstance().HandlePauseAllOperation();
    Media::EnhancementManager::GetInstance().HandleResumeAllOperation();
    Media::EnhancementManager::GetInstance().HandleStateChangedOperation(FuzzBool(data, size));
    Media::EnhancementManager::GetInstance().HandleNetChange(FuzzBool(data, size), FuzzBool(data, size));
    string photosAutoOption = Media::PHOTO_OPTION_CLOSE;
    if (FuzzBool(data, size)) {
        photosAutoOption = FuzzString(data, size);
    }
    Media::EnhancementManager::GetInstance().HandlePhotosAutoOptionChange(photosAutoOption);
    Media::EnhancementManager::GetInstance().HandlePhotosWaterMarkChange(FuzzBool(data, size));
    Media::EnhancementManager::GetInstance().InitAsync();
}

static void EnhancementTaskManagerTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count) {
        return;
    }
    int32_t offset = 0;
    int32_t fileId = FuzzInt32(data + offset, size);
    string photoId = FuzzString(data, size);
    Media::EnhancementTaskManager::AddEnhancementTask(fileId, photoId, 0);
    Media::EnhancementTaskManager::RemoveEnhancementTask(photoId);
    Media::EnhancementTaskManager::RemoveEnhancementTask(photoId);

    vector<string> taskIds = FuzzVectorString(data, size);
    Media::EnhancementTaskManager::RemoveAllEnhancementTask(taskIds);
    offset += sizeof(int32_t);
    fileId = FuzzInt32(data + offset, size);
    photoId = FuzzString(data, size);
    Media::EnhancementTaskManager::AddEnhancementTask(fileId, photoId, 0);
    Media::EnhancementTaskManager::InProcessingTask(photoId);
    Media::EnhancementTaskManager::QueryPhotoIdByFileId(fileId);

    photoId = FuzzString(data, size);
    offset += sizeof(int32_t);
    Media::EnhancementTaskManager::SetTaskRequestCount(photoId, FuzzInt32(data + offset, size));
    Media::EnhancementTaskManager::GetTaskRequestCount(photoId);
}

static void CloudEnhancementGetCountTest(const uint8_t *data, size_t size)
{
    Media::CloudEnhancementGetCount& cloudEnhancementGetCount = Media::CloudEnhancementGetCount::GetInstance();
    cloudEnhancementGetCount.GetStartTimes();
    string photoId = FuzzString(data, size);
    cloudEnhancementGetCount.AddStartTime(photoId);
    cloudEnhancementGetCount.Report(FuzzString(data, size), photoId, 0);
    cloudEnhancementGetCount.RemoveStartTime(photoId);
    cloudEnhancementGetCount.RemoveStartTime(photoId);
}

static void EnhancementServiceAdpterTest(const uint8_t *data, size_t size)
{
    shared_ptr<Media::EnhancementServiceAdapter> enhancementService = make_shared<Media::EnhancementServiceAdapter>();
    enhancementService->LoadEnhancementService();

    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    string photoId = FuzzString(data, size);
    enhancementService->AddTask(FuzzString(data, size), mediaEnhanceBundle);
    enhancementService->RemoveTask(FuzzString(data, size));
    enhancementService->CancelTask(FuzzString(data, size));
    enhancementService->CancelAllTasks();

    vector<string> taskIdList = FuzzVectorString(data, size);
    enhancementService->GetPendingTasks(taskIdList);
}

static void EnhancementServiceCallbackTest(const uint8_t *data, size_t size)
{
    const int32_t int32Count = 3;
    if (data == nullptr || size < sizeof(int32_t) * int32Count + sizeof(uint32_t)) {
        return;
    }
    Media::EnhancementServiceCallback::OnServiceReconnected();

    string photoId = FuzzString(data, size);
    MediaEnhance::MediaEnhanceBundleHandle* bundle = FuzzMediaEnhanceBundle(data, size, photoId);
    Media::EnhancementServiceCallback::OnSuccess(photoId.c_str(), bundle);
    photoId = FuzzString(data, size);
    bundle = FuzzMediaEnhanceBundle(data, size, photoId);
    Media::EnhancementServiceCallback::OnFailed(photoId.c_str(), bundle);

    uint32_t bufferSize = static_cast<uint32_t>(sizeof(Media::BUFFER));
    uint8_t* buffer = new uint8_t[bufferSize];
    for (uint32_t i = 0; i < bufferSize; i++) {
        buffer[i] = Media::BUFFER[i];
    }
    string displayName = FuzzString(data, size) + ".jpg";
    int32_t hidden = FuzzBool(data, size) ? YES : NO;
    int32_t offset = 0;
    int32_t fileId = FuzzInt32(data + offset, size);
    shared_ptr<Media::CloudEnhancementFileInfo> fileInfo = make_shared<Media::CloudEnhancementFileInfo>(
        fileId, FuzzString(data, size), displayName, FuzzPhotoSubType(data, size), hidden);
    offset += sizeof(int32_t);
    int32_t statusCode = FuzzInt32(data + offset, size);
    offset += sizeof(uint32_t);
    uint32_t bytes = FuzzUInt32(data + offset, size);
    Media::CloudEnhancementThreadTask task(FuzzString(data, size),
        statusCode, buffer, bytes, FuzzBool(data, size));
    vector<string> columns;
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO,
        Media::OperationType::QUERY, Media::MediaLibraryApi::API_10);
    cmd.GetAbsRdbPredicates()->EqualTo(Media::PhotoColumn::PHOTO_ID, photoId);
    auto resultSet = g_rdbStore->Query(cmd, columns);
    if (resultSet != nullptr && resultSet->GoToFirstRow() == E_OK) {
        Media::EnhancementServiceCallback::SaveCloudEnhancementPhoto(fileInfo, task, resultSet);
        offset += sizeof(int32_t);
        int32_t sourceFileId = FuzzInt32(data + offset, size);
        Media::EnhancementServiceCallback::CreateCloudEnhancementPhoto(sourceFileId, fileInfo,
            resultSet);
    }
    Media::EnhancementServiceCallback::DealWithSuccessedTask(task);
    Media::EnhancementServiceCallback::DealWithFailedTask(task);
    Media::EnhancementServiceCallback::UpdateAlbumsForCloudEnhancement();
}
#endif
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    OHOS::Init();
#endif
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    OHOS::EnhancementManagerTest(data, size);
    OHOS::EnhancementManagerExtraTest(data, size);
    OHOS::EnhancementTaskManagerTest(data, size);
    OHOS::CloudEnhancementGetCountTest(data, size);
    OHOS::EnhancementServiceAdpterTest(data, size);
    OHOS::EnhancementServiceCallbackTest(data, size);
#endif
    int sleepTime = 100;
    std::this_thread::sleep_for(std::chrono::microseconds(sleepTime));
    return 0;
}