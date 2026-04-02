/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#define MLOG_TAG "CloudMediaDownloadDaoTest"

#include "cloud_media_download_dao_test.h"

#include "media_log.h"
#include "result_set_utils.h"
#include "media_file_utils.h"
#include "medialibrary_db_const_sqls.h"
#include "medialibrary_unittest_utils.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_photo_operations.h"
#include "fetch_result.h"
#include "media_column.h"
#include "cloud_media_download_dao.h"
#include "cloud_media_dao_utils.h"
#include "cloud_media_define.h"
#include "media_cloud_sync_test_utils.h"

#include <string>
#include <vector>

namespace OHOS::Media::CloudSync {
using namespace testing::ext;
using namespace OHOS::NativeRdb;

static std::shared_ptr<MediaLibraryRdbStore> g_rdbStore;

void CloudMediaDownloadDaoTest::SetUpTestCase(void)
{
    GTEST_LOG_(INFO) << "SetUpTestCase";
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "Start CloudMediaDownloadDaoTest failed, can not get rdbstore";
        exit(1);
    }
    SetTestTables(g_rdbStore);
}

void CloudMediaDownloadDaoTest::TearDownTestCase(void)
{
    GTEST_LOG_(INFO) << "TearDownTestCase";
    if (!MediaLibraryUnitTestUtils::IsValid()) {
        MediaLibraryUnitTestUtils::Init();
    }
    system("rm -rf /storage/cloud/files/*");
    ClearAndRestart(g_rdbStore);
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

void CloudMediaDownloadDaoTest::SetUp()
{
    if (g_rdbStore == nullptr) {
        GTEST_LOG_(ERROR) << "Start CloudMediaDownloadDaoTest failed, can not get rdbstore";
        exit(1);
    }
    ClearAndRestart(g_rdbStore);
}

void CloudMediaDownloadDaoTest::TearDown()
{}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThmNum_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    int32_t type = static_cast<int32_t>(ThmLcdState::THM);
    int32_t totalNum = 0;
    
    int32_t ret = downloadDao.GetDownloadThmNum(type, totalNum);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(totalNum, 0);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThmNum_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    int32_t type = static_cast<int32_t>(ThmLcdState::LCD);
    int32_t totalNum = 0;
    
    int32_t ret = downloadDao.GetDownloadThmNum(type, totalNum);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(totalNum, 0);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThmNum_Test_003, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    int32_t type = static_cast<int32_t>(ThmLcdState::THMLCD);
    int32_t totalNum = 0;
    
    int32_t ret = downloadDao.GetDownloadThmNum(type, totalNum);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(totalNum, 0);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThmNum_Test_004, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    int32_t type = 999;
    int32_t totalNum = 0;
    
    int32_t ret = downloadDao.GetDownloadThmNum(type, totalNum);
    EXPECT_EQ(ret, E_OK);
    EXPECT_GE(totalNum, 0);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThms_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    DownloadThumbnailQueryDto queryDto;
    queryDto.type = static_cast<int32_t>(ThmLcdState::THM);
    queryDto.size = 10;
    queryDto.offset = 0;
    queryDto.isDownloadDisplayFirst = false;
    
    std::vector<PhotosPo> photos;
    int32_t ret = downloadDao.GetDownloadThms(queryDto, photos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThms_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    DownloadThumbnailQueryDto queryDto;
    queryDto.type = static_cast<int32_t>(ThmLcdState::THM);
    queryDto.size = 10;
    queryDto.offset = 0;
    queryDto.isDownloadDisplayFirst = true;
    
    std::vector<PhotosPo> photos;
    int32_t ret = downloadDao.GetDownloadThms(queryDto, photos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThms_Test_003, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    DownloadThumbnailQueryDto queryDto;
    queryDto.type = static_cast<int32_t>(ThmLcdState::LCD);
    queryDto.size = 10;
    queryDto.offset = 0;
    queryDto.isDownloadDisplayFirst = false;
    
    std::vector<PhotosPo> photos;
    int32_t ret = downloadDao.GetDownloadThms(queryDto, photos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadThms_Test_004, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    DownloadThumbnailQueryDto queryDto;
    queryDto.type = static_cast<int32_t>(ThmLcdState::THMLCD);
    queryDto.size = 10;
    queryDto.offset = 0;
    queryDto.isDownloadDisplayFirst = false;
    
    std::vector<PhotosPo> photos;
    int32_t ret = downloadDao.GetDownloadThms(queryDto, photos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadAsset_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<int32_t> fileIds;
    std::vector<PhotosPo> photos;
    
    int32_t ret = downloadDao.GetDownloadAsset(fileIds, photos);
    EXPECT_EQ(ret, E_OK);
    EXPECT_EQ(photos.size(), 0);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetDownloadAsset_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<int32_t> fileIds = {1, 2, 3};
    std::vector<PhotosPo> photos;
    
    int32_t ret = downloadDao.GetDownloadAsset(fileIds, photos);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadThm_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds;
    
    int32_t ret = downloadDao.UpdateDownloadThm(cloudIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadLcd_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds;
    
    int32_t ret = downloadDao.UpdateDownloadLcd(cloudIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadThmAndLcd_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds;
    
    int32_t ret = downloadDao.UpdateDownloadThmAndLcd(cloudIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadThmAndLcd_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds = {"cloud_id_1", "cloud_id_2"};
    
    int32_t ret = downloadDao.UpdateDownloadThmAndLcd(cloudIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetFileIdFromCloudId_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds;
    std::vector<std::string> FileIds;
    
    int32_t ret = downloadDao.GetFileIdFromCloudId(cloudIds, FileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, GetFileIdFromCloudId_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds = {"cloud_id_1", "cloud_id_2"};
    std::vector<std::string> fileIds;
    
    int32_t ret = downloadDao.GetFileIdFromCloudId(cloudIds, fileIds);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, QueryDownloadAssetByCloudIds_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds;
    std::vector<PhotosPo> result;
    
    int32_t ret = downloadDao.QueryDownloadAssetByCloudIds(cloudIds, result);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, QueryDownloadAssetByCloudIds_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::vector<std::string> cloudIds = {"cloud_id_1", "cloud_id_2"};
    std::vector<PhotosPo> result;
    
    int32_t ret = downloadDao.QueryDownloadAssetByCloudIds(cloudIds, result);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateTransCodeInfo_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    std::string path = "/storage/test.jpg";
    
    int32_t ret = downloadDao.UpdateTransCodeInfo(path);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = false;
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = true;
    assetData.path = "/storage/test.jpg";
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = false;
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_003, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    assetData.needScanHdrMode = false;
    assetData.needScanSubtype = false;
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = true;
    scanResult.hdrMode = 1;
    scanResult.subType = 0;
    scanResult.height = 1920;
    scanResult.width = 1080;
    scanResult.orientation = 0;
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_005, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    assetData.needScanSubtype = true;
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = true;
    scanResult.subType = static_cast<int32_t>(PhotoSubType::SPATIAL_3DGS);
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_006, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    assetData.needScanSubtype = true;
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = true;
    scanResult.subType = static_cast<int32_t>(PhotoSubType::SLOW_MOTION_VIDEO);
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_007, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    assetData.needScanSubtype = true;
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = true;
    scanResult.subType = 0;
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAssetExifRotateFix_Test_001, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t fileId = 1;
    int32_t exifRotate = 90;
    DirtyTypes dirtyType = DirtyTypes::TYPE_MDIRTY;
    bool needRegenerateThumbnail = true;
    
    int32_t ret = downloadDao.UpdateDownloadAssetExifRotateFix(photoRefresh,
        fileId, exifRotate, dirtyType, needRegenerateThumbnail);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAssetExifRotateFix_Test_002, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t fileId = 1;
    int32_t exifRotate = 90;
    DirtyTypes dirtyType = DirtyTypes::TYPE_FDIRTY;
    bool needRegenerateThumbnail = false;
    
    int32_t ret = downloadDao.UpdateDownloadAssetExifRotateFix(photoRefresh,
            fileId, exifRotate, dirtyType, needRegenerateThumbnail);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAssetExifRotateFix_Test_003, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    auto photoRefresh = std::make_shared<AccurateRefresh::AssetAccurateRefresh>();
    int32_t fileId = 1;
    int32_t exifRotate = 90;
    DirtyTypes dirtyType = DirtyTypes::TYPE_MDIRTY;
    bool needRegenerateThumbnail = false;
    
    int32_t ret = downloadDao.UpdateDownloadAssetExifRotateFix(photoRefresh,
        fileId, exifRotate, dirtyType, needRegenerateThumbnail);
    EXPECT_EQ(ret, E_OK);
}

HWTEST_F(CloudMediaDownloadDaoTest, UpdateDownloadAsset_Test_004, TestSize.Level1)
{
    CloudMediaDownloadDao downloadDao;
    OnDownloadAssetData assetData;
    assetData.fixFileType = false;
    assetData.path = "/storage/test.jpg";
    
    AdditionFileInfo lakeInfo;
    lakeInfo.isUpdate = true;
    lakeInfo.fileSourceType = 1;
    lakeInfo.storagePath = "/storage/lake/path.jpg";
    lakeInfo.title = "title";
    lakeInfo.displayName = "display.jpg";
    assetData.lakeInfo = lakeInfo;
    
    CloudMediaScanService::ScanResult scanResult;
    scanResult.scanSuccess = false;
    
    int32_t ret = downloadDao.UpdateDownloadAsset(assetData, scanResult);
    EXPECT_EQ(ret, E_OK);
}
}  // namespace OHOS::Media::CloudSync
