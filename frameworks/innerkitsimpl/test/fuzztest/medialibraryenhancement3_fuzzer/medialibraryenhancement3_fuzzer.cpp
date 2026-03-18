/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "medialibraryenhancement3_fuzzer.h"
#include "medialibrary_rdbstore_utils_fuzzer.h"

#include <cstdint>
#include <string>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "ability_context_impl.h"
#include "medialibrary_photo_operations.h"
#include "media_log.h"
#include "media_upgrade.h"

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
#include "enhancement_manager.h"
#endif

namespace OHOS {
using namespace std;
using namespace AbilityRuntime;
using namespace DataShare;
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static const string TESTING_DISPLAYNAME = "IMG_20240904_133901.jpg";
static const int32_t NO = 0;
static const int32_t YES = 1;
static const int32_t NUM_BYTES = 1;
static const int32_t MAX_PHOTO_QUALITY = 1;
static const int32_t MAX_ENHANCEMENT_FUZZER_URI_LISTS = 6;
static const int32_t MAX_CLOUD_ENHANCEMENT_AVAILABLE_TYPE = 8;
static const int32_t MAX_BYTE_VALUE = 256;
static const int32_t SEED_SIZE = 1024;
static const string PHOTOS_TABLE = "Photos";
static const string PHOTO_URI_PREFIX = "file://media/Photo/";
static const string PHOTO_URI_PREFIX_UNDEDINED = "undedined/";
std::shared_ptr<Media::MediaLibraryRdbStore> g_rdbStore;
FuzzedDataProvider *provider = nullptr;

static inline Uri FuzzUriWithKeyValue(string uriStr)
{
    if (provider->ConsumeBool()) {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, CONST_MEDIA_OPERN_KEYWORD, "true");
    } else {
        Media::MediaFileUtils::UriAppendKeyValue(uriStr, CONST_MEDIA_OPERN_KEYWORD, "false");
    }
    Uri addTask(uriStr);
    return addTask;
}

static inline Uri FuzzUri()
{
    uint8_t data = provider->ConsumeIntegralInRange<uint8_t>(0, MAX_ENHANCEMENT_FUZZER_URI_LISTS);
    string uriStr = Media::ENHANCEMENT_FUZZER_URI_LISTS[data];
    return FuzzUriWithKeyValue(uriStr);
}

static inline Media::MediaLibraryCommand FuzzMediaLibraryCmd()
{
    return Media::MediaLibraryCommand(FuzzUri());
}

static inline Media::CloudEnhancementAvailableType FuzzCloudEnhancementAvailableType()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_CLOUD_ENHANCEMENT_AVAILABLE_TYPE);
    return static_cast<Media::CloudEnhancementAvailableType>(value);
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

static inline Media::MultiStagesPhotoQuality FuzzMultiStagesPhotoQuality()
{
    int32_t value = provider->ConsumeIntegralInRange<int32_t>(0, MAX_PHOTO_QUALITY);
    return static_cast<Media::MultiStagesPhotoQuality>(value);
}

int32_t PrepareHighQualityPhoto(const string &photoId, const string &displayName)
{
    auto fileId = SetDefaultPhotoApi10(Media::MediaType::MEDIA_TYPE_IMAGE, displayName);
    // update multi-stages capture db info
    Media::MediaLibraryCommand cmd(Media::OperationObject::FILESYSTEM_PHOTO, Media::OperationType::UPDATE,
        Media::MediaLibraryApi::API_10);
    NativeRdb::ValuesBucket values;
    values.Put(Media::PhotoColumn::PHOTO_QUALITY, static_cast<int32_t>(FuzzMultiStagesPhotoQuality()));
    values.Put(Media::PhotoColumn::PHOTO_CE_AVAILABLE,
        static_cast<int32_t>(FuzzCloudEnhancementAvailableType()));
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
#endif

#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
static void Init()
{
    auto stageContext = std::make_shared<AbilityRuntime::ContextImpl>();
    auto abilityContextImpl = std::make_shared<OHOS::AbilityRuntime::AbilityContextImpl>();
    abilityContextImpl->SetStageContext(stageContext);
    auto rdbStore = Media::MediaLibraryRdbStoreUtilsTest::InitMediaLibraryRdbStore(abilityContextImpl);
    if (rdbStore == nullptr) {
        MEDIA_ERR_LOG("rdbStore is nullptr");
        return;
    }
    g_rdbStore = rdbStore;
    Media::EnhancementManager::GetInstance().Init();
}

static void EnhancementManagerTest()
{
    string TESTING_PHOTO_ID = to_string(provider->ConsumeIntegral<uint32_t>());
    int32_t fileId = PrepareHighQualityPhoto(TESTING_PHOTO_ID, TESTING_DISPLAYNAME);
    UpdateCEAvailable(fileId, static_cast<int32_t>(FuzzCloudEnhancementAvailableType()));
    
    vector<string> fileIds = { to_string(fileId) };
    vector<string> photoIds;
    Media::EnhancementManager::GetInstance().CancelTasksInternal(fileIds, photoIds,
        FuzzCloudEnhancementAvailableType());
    Media::EnhancementManager::GetInstance().RemoveTasksInternal(fileIds, photoIds);
    Media::EnhancementManager::GetInstance().RevertEditUpdateInternal(fileId);
    Media::EnhancementManager::GetInstance().RecoverTrashUpdateInternal(fileIds);

    DataSharePredicates predicates;
    string prefix = provider->ConsumeBool() ? PHOTO_URI_PREFIX : PHOTO_URI_PREFIX_UNDEDINED;
    string photoUri = prefix + "1/IMG_1722329102_000/" + TESTING_DISPLAYNAME;
    predicates.EqualTo(Media::MediaColumn::MEDIA_ID, photoUri);
    int32_t hasCloudWatermark = provider->ConsumeBool() ? YES : NO;
    predicates.EqualTo(Media::PhotoColumn::PHOTO_HAS_CLOUD_WATERMARK, hasCloudWatermark);
    Media::MediaLibraryCommand cmd = FuzzMediaLibraryCmd();
    cmd.SetDataSharePred(predicates);
    Media::EnhancementManager::GetInstance().HandleEnhancementUpdateOperation(cmd);
    vector<string> columns = {provider->ConsumeBytesAsString(NUM_BYTES)};
    Media::EnhancementManager::GetInstance().HandleEnhancementQueryOperation(cmd, columns);

    MediaEnhance::MediaEnhanceBundleHandle* mediaEnhanceBundle
        = Media::EnhancementManager::GetInstance().enhancementService_->CreateBundle();
    Media::EnhancementManager::GetInstance().AddServiceTask(mediaEnhanceBundle, provider->ConsumeIntegral<int32_t>(),
        provider->ConsumeBytesAsString(NUM_BYTES), provider->ConsumeBool());
}

static int32_t AddSeed()
{
    char *seedData = new char[OHOS::SEED_SIZE];
    for (int i = 0; i < OHOS::SEED_SIZE; i++) {
        seedData[i] = static_cast<char>(i % MAX_BYTE_VALUE);
    }

    const char* filename = "corpus/seed.txt";
    std::ofstream file(filename, std::ios::binary | std::ios::trunc);
    if (!file) {
        MEDIA_ERR_LOG("Cannot open file filename:%{public}s", filename);
        delete[] seedData;
        return Media::E_ERR;
    }
    file.write(seedData, OHOS::SEED_SIZE);
    file.close();
    delete[] seedData;
    MEDIA_INFO_LOG("seedData has been successfully written to file filename:%{public}s", filename);
    return Media::E_OK;
}
#endif
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    OHOS::AddSeed();
    OHOS::Init();
#endif
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#ifdef ABILITY_CLOUD_ENHANCEMENT_SUPPORT
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::provider = &fdp;

    OHOS::EnhancementManagerTest();
#endif
    return 0;
}