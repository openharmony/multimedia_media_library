/*
* Copyright (C) 2024 Huawei Device Co., Ltd.
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#define MLOG_TAG "MediaAssetTest"

#include <thread>
#include "file_asset.h"
#include "media_asset_test.h"
#include "media_asset_base_capi.h"
#include "media_asset_manager_capi.h"
#include "media_asset_capi.h"
#include "oh_media_asset.h"
#include "media_asset.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;

void MediaAssetTest::SetUpTestCase(void) {}

void MediaAssetTest::TearDownTestCase(void) {}

void MediaAssetTest::SetUp(void) {}

void MediaAssetTest::TearDown(void) {}

void MediaAssetTest::FreeCharPointer(const char *freeCharPointer)
{
    if (freeCharPointer != nullptr) {
        freeCharPointer = nullptr;
    }
}

HWTEST_F(MediaAssetTest, mediaAsset_GetUri_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    const char *uri = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(uri);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetUri_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDisplayName_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    const char *displayName = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(displayName);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDisplayName_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetSize_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t size = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(mediaAsset, &size);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetSize_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t size = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(nullptr, &size);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetSize(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModifiedMs_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateModifiedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModifiedMs_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateModifiedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModifiedMs(nullptr, &dateModifiedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateModifiedMs(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetWidth_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t width = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetWidth(mediaAsset, &width);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetWidth_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t width = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetWidth(nullptr, &width);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetWidth(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetHeight_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t height = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetHeight(mediaAsset, &height);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetHeight_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t height = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetHeight(nullptr, &height);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetHeight(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetOrientation_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetOrientation_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Release_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(nullptr), MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetMediaType_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetMediaType_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetMediaType(nullptr, &mediaType);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetMediaSubType_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_BURST;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaSubType(mediaAsset, &mediaSubType);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetMediaSubType_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaSubType(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateAdded_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateAdded = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateAdded_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateAdded = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateAdded(nullptr, &dateAdded);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateAdded(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModified_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateModified = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateModified_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateModified = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateModified(nullptr, &dateModified);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateModified(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateTaken_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateTaken = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateTaken_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateTaken = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateTaken(nullptr, &dateTaken);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateTaken(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateAddedMs_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateAddedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDateAddedMs_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t dateAddedMs = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDateAddedMs(nullptr, &dateAddedMs);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDateAddedMs(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDuration_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t duration = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDuration(mediaAsset, &duration);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetDuration_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t duration = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDuration(nullptr, &duration);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_GetDuration(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_IsFavorite_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t favorite = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_IsFavorite(mediaAsset, &favorite);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_IsFavorite_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    uint32_t favorite = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_IsFavorite(nullptr, &favorite);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    ret = OH_MediaAsset_IsFavorite(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetTitle_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    const char *title = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetTitle(mediaAsset, &title);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(title);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetTitle_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetTitle(mediaAsset, nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetTitle_test_003, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    const char *title = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetTitle(mediaAsset, &title);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_NE(title, nullptr);
    FreeCharPointer(title);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_GetTitle_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    const char *title = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetTitle(mediaAsset, &title);
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    FreeCharPointer(title);
}

HWTEST_F(MediaAssetTest, mediaAsset_MultipleGetters_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_DateGetters_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_NullPointer_test_001, TestSize.Level1)
{
    const char *uri = nullptr;
    uint32_t size = 0;
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(nullptr, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetSize(nullptr, &size);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_NullPointer_test_002, TestSize.Level1)
{
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_BURST;
    uint32_t duration = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetMediaType(nullptr, &mediaType);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetMediaSubType(nullptr, &mediaSubType);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDuration(nullptr, &duration);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_NullPointerOutput_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(nullptr, nullptr);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetSize(nullptr, nullptr);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Release_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Release_test_003, TestSize.Level1)
{
    MediaLibrary_ErrorCode ret = OH_MediaAsset_Release(nullptr);
    EXPECT_EQ(ret, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 100; i++) {
        const char *uri = nullptr;
        uint32_t size = 0;
        MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
        MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetSize(mediaAsset, &size);
        
        EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
        EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(uri);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_002, TestSize.Level1)
{
    for (int i = 0; i < 50; i++) {
        std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
        auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
        auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
        
        const char *displayName = nullptr;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(displayName);
        EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
    }
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaType, MEDIA_LIBRARY_IMAGE);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_VIDEO);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaType, MEDIA_LIBRARY_VIDEO);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(orientation, 0);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    uint32_t size = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_003, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllGetters_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *displayName = nullptr;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(displayName);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_001, TestSize.Level1)
{
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_BURST;
    uint32_t dateAdded = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(nullptr, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(nullptr, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(nullptr, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(nullptr, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(nullptr, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(nullptr, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(nullptr, &mediaType);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(nullptr, &mediaSubType);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(nullptr, &dateAdded);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret11 = OH_MediaAsset_GetDateModified(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret12 = OH_MediaAsset_GetDateTaken(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret13 = OH_MediaAsset_GetDateAddedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret14 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret15 = OH_MediaAsset_GetDuration(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret16 = OH_MediaAsset_IsFavorite(mediaAsset, nullptr);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret11, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret12, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret13, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret14, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret15, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret16, MEDIA_LIBRARY_PARAMETER_ERROR);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MediaTypeValidation_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_VIDEO;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaType, MEDIA_LIBRARY_IMAGE);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MediaTypeValidation_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_VIDEO);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaType, MEDIA_LIBRARY_VIDEO);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 10; i++) {
        const char *uri = nullptr;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(uri);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 10; i++) {
        uint32_t size = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(mediaAsset, &size);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Validation_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Validation_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 10; i++) {
        uint32_t height = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetHeight(mediaAsset, &height);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 10; i++) {
        uint32_t width = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetWidth(mediaAsset, &width);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    uint32_t size = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_003, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 100; i++) {
        const char *title = nullptr;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetTitle(mediaAsset, &title);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(title);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 50; i++) {
        uint32_t duration = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetDuration(mediaAsset, &duration);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t favorite = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_IsFavorite(mediaAsset, &favorite);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(favorite, 0);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t orientation = 0;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(orientation, 0);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_007, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t width = 0;
    uint32_t height = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllGetters_test_002, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_003, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_003, TestSize.Level1)
{
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_BURST;
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(nullptr, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(nullptr, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(nullptr, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(nullptr, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(nullptr, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(nullptr, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(nullptr, &mediaType);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(nullptr, &mediaSubType);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(nullptr, &dateAdded);
    MediaLibrary_ErrorCode ret11 = OH_MediaAsset_GetDateModified(nullptr, &dateModified);
    MediaLibrary_ErrorCode ret12 = OH_MediaAsset_GetDateTaken(nullptr, &dateTaken);
    MediaLibrary_ErrorCode ret13 = OH_MediaAsset_GetDateAddedMs(nullptr, &dateAddedMs);
    MediaLibrary_ErrorCode ret14 = OH_MediaAsset_GetDateModifiedMs(nullptr, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret11, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret12, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret13, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret14, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret11 = OH_MediaAsset_GetDateModified(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret12 = OH_MediaAsset_GetDateTaken(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret13 = OH_MediaAsset_GetDateAddedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret14 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret15 = OH_MediaAsset_GetDuration(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret16 = OH_MediaAsset_IsFavorite(mediaAsset, nullptr);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret11, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret12, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret13, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret14, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret15, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret16, MEDIA_LIBRARY_PARAMETER_ERROR);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MediaTypeValidation_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    fileAsset->SetMediaType(OHOS::Media::MEDIA_TYPE_IMAGE);
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_VIDEO;
    MediaLibrary_ErrorCode ret = OH_MediaAsset_GetMediaType(mediaAsset, &mediaType);
    
    EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    EXPECT_EQ(mediaType, MEDIA_LIBRARY_IMAGE);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 20; i++) {
        const char *uri = nullptr;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(uri);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_ConsecutiveCalls_test_007, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 15; i++) {
        uint32_t size = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetSize(mediaAsset, &size);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Validation_test_004, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Validation_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 75; i++) {
        uint32_t favorite = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_IsFavorite(mediaAsset, &favorite);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Stress_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 60; i++) {
        uint32_t orientation = 0;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_008, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_EdgeCase_test_009, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    uint32_t duration = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDuration(mediaAsset, &duration);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_Integration_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllGetters_test_003, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_005, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_MemoryLeak_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetDateAdded(mediaAsset, &dateAdded);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDateModified(mediaAsset, &dateModified);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetDateTaken(mediaAsset, &dateTaken);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetDateAddedMs(mediaAsset, &dateAddedMs);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_005, TestSize.Level1)
{
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    MediaLibrary_MediaType mediaType = MEDIA_LIBRARY_IMAGE;
    MediaLibrary_MediaSubType mediaSubType = MEDIA_LIBRARY_BURST;
    uint32_t dateAdded = 0;
    uint32_t dateModified = 0;
    uint32_t dateTaken = 0;
    uint32_t dateAddedMs = 0;
    uint32_t dateModifiedMs = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(nullptr, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(nullptr, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(nullptr, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(nullptr, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(nullptr, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(nullptr, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(nullptr, &orientation);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(nullptr, &mediaType);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(nullptr, &mediaSubType);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(nullptr, &dateAdded);
    MediaLibrary_ErrorCode ret11 = OH_MediaAsset_GetDateModified(nullptr, &dateModified);
    MediaLibrary_ErrorCode ret12 = OH_MediaAsset_GetDateTaken(nullptr, &dateTaken);
    MediaLibrary_ErrorCode ret13 = OH_MediaAsset_GetDateAddedMs(nullptr, &dateAddedMs);
    MediaLibrary_ErrorCode ret14 = OH_MediaAsset_GetDateModifiedMs(nullptr, &dateModifiedMs);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret11, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret12, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret13, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret14, MEDIA_LIBRARY_PARAMETER_ERROR);
}

HWTEST_F(MediaAssetTest, mediaAsset_AllNullChecks_test_006, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret8 = OH_MediaAsset_GetMediaType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret9 = OH_MediaAsset_GetMediaSubType(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret10 = OH_MediaAsset_GetDateAdded(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret11 = OH_MediaAsset_GetDateModified(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret12 = OH_MediaAsset_GetDateTaken(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret13 = OH_MediaAsset_GetDateAddedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret14 = OH_MediaAsset_GetDateModifiedMs(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret15 = OH_MediaAsset_GetDuration(mediaAsset, nullptr);
    MediaLibrary_ErrorCode ret16 = OH_MediaAsset_IsFavorite(mediaAsset, nullptr);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret8, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret9, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret10, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret11, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret12, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret13, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret14, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret15, MEDIA_LIBRARY_PARAMETER_ERROR);
    EXPECT_EQ(ret16, MEDIA_LIBRARY_PARAMETER_ERROR);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_FinalIntegration_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    const char *uri = nullptr;
    const char *displayName = nullptr;
    const char *title = nullptr;
    uint32_t size = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t orientation = 0;
    
    MediaLibrary_ErrorCode ret1 = OH_MediaAsset_GetUri(mediaAsset, &uri);
    MediaLibrary_ErrorCode ret2 = OH_MediaAsset_GetDisplayName(mediaAsset, &displayName);
    MediaLibrary_ErrorCode ret3 = OH_MediaAsset_GetTitle(mediaAsset, &title);
    MediaLibrary_ErrorCode ret4 = OH_MediaAsset_GetSize(mediaAsset, &size);
    MediaLibrary_ErrorCode ret5 = OH_MediaAsset_GetWidth(mediaAsset, &width);
    MediaLibrary_ErrorCode ret6 = OH_MediaAsset_GetHeight(mediaAsset, &height);
    MediaLibrary_ErrorCode ret7 = OH_MediaAsset_GetOrientation(mediaAsset, &orientation);
    
    EXPECT_EQ(ret1, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret2, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret3, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret4, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret5, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret6, MEDIA_LIBRARY_OK);
    EXPECT_EQ(ret7, MEDIA_LIBRARY_OK);
    
    FreeCharPointer(uri);
    FreeCharPointer(displayName);
    FreeCharPointer(title);
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

HWTEST_F(MediaAssetTest, mediaAsset_FinalStress_test_001, TestSize.Level1)
{
    std::shared_ptr<FileAsset> fileAsset = std::make_shared<FileAsset>();
    auto mediaAssetImpl = MediaAssetFactory::CreateMediaAsset(fileAsset);
    auto* mediaAsset = new OH_MediaAsset(mediaAssetImpl);
    
    for (int i = 0; i < 150; i++) {
        const char *uri = nullptr;
        MediaLibrary_ErrorCode ret = OH_MediaAsset_GetUri(mediaAsset, &uri);
        
        EXPECT_EQ(ret, MEDIA_LIBRARY_OK);
        
        FreeCharPointer(uri);
    }
    
    EXPECT_EQ(OH_MediaAsset_Release(mediaAsset), MEDIA_LIBRARY_OK);
}

} // namespace Media
} // namespace OHOS