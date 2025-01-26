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

#include "medialibrary_astc_phase_test.h"
#include "medialibrary_unittest_utils.h"

#include "medialibrary_uripermission_operations.h"
#include "media_log.h"

#include "fetch_result.h"
#include "get_self_permissions.h"
#include "media_file_ext_ability.h"
#include "media_file_extention_utils.h"
#include "media_file_utils.h"
#include "media_smart_map_column.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "medialibrary_unittest_utils.h"
#include "uri.h"
#include "photo_album_column.h"
#include "medialibrary_unistore_manager.h"
#include "result_set_utils.h"
#include "photo_file_utils.h"
#include "photo_map_column.h"
#include "scanner_utils.h"
#include "medialibrary_photo_operations.h"
#include "media_file_uri.h"

#define private public
#include "medialibrary_astc_stat.h"
#undef private

using namespace std;
using namespace testing::ext;


namespace OHOS {
namespace Media {

void MediaLibraryAstcPhaseUnitTest::SetUpTestCase(void)
{
    MediaLibraryUnitTestUtils::Init();
    vector<string> perms;
    perms.push_back("ohos.permission.MEDIA_LOCATION");
    perms.push_back("ohos.permission.GET_BUNDLE_INFO_PRIVILEGED");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaLibraryAstcPhaseUnitTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    system("param set hiviewdfx.hiview.testtype TDD");
}


void MediaLibraryAstcPhaseUnitTest::TearDownTestCase(void)
{
}

// SetUp:Execute before each test case
void MediaLibraryAstcPhaseUnitTest::SetUp(void)
{
    MediaLibraryUnitTestUtils::CleanBundlePermission();
    MediaLibraryUnitTestUtils::InitRootDirs();
    MediaLibraryUnitTestUtils::Init();
    MediaLibraryAstcStat::GetInstance().ClearOldData();
}

void MediaLibraryAstcPhaseUnitTest::TearDown(void) {}

HWTEST_F(MediaLibraryAstcPhaseUnitTest, AstcPhase_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("AstcPhase_001::Start");
    int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
    auto& mediaLibraryAstcStat = MediaLibraryAstcStat::GetInstance();
    mediaLibraryAstcStat.AddAstcInfo(start, OHOS::Media::GenerateScene::BACKGROUND,
        OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF);
    EXPECT_EQ(mediaLibraryAstcStat.totalAstcCount_, 1);
    EXPECT_EQ(mediaLibraryAstcStat.phasesStat_.phases_.size(), 1);
    EXPECT_EQ(mediaLibraryAstcStat.phasesStat_.phases_.count(OHOS::Media::AstcPhase::PHASE1), 1);
    auto& phaseStat = mediaLibraryAstcStat.phasesStat_.phases_[OHOS::Media::AstcPhase::PHASE1];
    EXPECT_EQ(phaseStat.phase_, OHOS::Media::AstcPhase::PHASE1);
    EXPECT_LE(phaseStat.startTime_, phaseStat.endTime_);
    EXPECT_EQ(phaseStat.scenes_.size(), 1);
    EXPECT_EQ(phaseStat.scenes_.count(OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF), 1);
    auto& scene = phaseStat.scenes_[OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF];
    EXPECT_EQ(scene.sceneKey_, OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF);
    EXPECT_LE(scene.duration_, phaseStat.endTime_ - phaseStat.startTime_);
    EXPECT_EQ(scene.astcCount_, 1);
    MEDIA_INFO_LOG("AstcPhase_001::End");
}

static void checkPhase2Case(MediaLibraryAstcStat& mediaLibraryAstcStat)
{
    int32_t astcTestCount = 100;
    int32_t astcTotalTestCount = 200;
    int32_t astcTestPhaseCount = 2;
    EXPECT_EQ(mediaLibraryAstcStat.totalAstcCount_, astcTotalTestCount);
    EXPECT_EQ(mediaLibraryAstcStat.phasesStat_.phases_.size(), astcTestPhaseCount);
    EXPECT_EQ(mediaLibraryAstcStat.phasesStat_.phases_.count(OHOS::Media::AstcPhase::PHASE1), 1);
    {
        auto& phaseStat = mediaLibraryAstcStat.phasesStat_.phases_[OHOS::Media::AstcPhase::PHASE1];
        EXPECT_EQ(phaseStat.phase_, OHOS::Media::AstcPhase::PHASE1);
        EXPECT_LE(phaseStat.startTime_, phaseStat.endTime_);
        EXPECT_EQ(phaseStat.scenes_.size(), 1);
        EXPECT_EQ(phaseStat.scenes_.count(OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF), 1);
        {
            auto& scene = phaseStat.scenes_[OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF];
            EXPECT_EQ(scene.sceneKey_, OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF);
            EXPECT_LE(scene.duration_, phaseStat.endTime_ - phaseStat.startTime_);
            EXPECT_EQ(scene.astcCount_, astcTestCount);
        }
    }

    EXPECT_EQ(mediaLibraryAstcStat.phasesStat_.phases_.count(OHOS::Media::AstcPhase::PHASE2), 1);
    {
        int32_t astcTestCount = 100;
        auto& phaseStat = mediaLibraryAstcStat.phasesStat_.phases_[OHOS::Media::AstcPhase::PHASE2];
        EXPECT_EQ(phaseStat.phase_, OHOS::Media::AstcPhase::PHASE2);
        EXPECT_LE(phaseStat.startTime_, phaseStat.endTime_);
        EXPECT_EQ(phaseStat.scenes_.size(), 1);
        EXPECT_EQ(phaseStat.scenes_.count(OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF), 1);
        {
            auto& scene = phaseStat.scenes_[OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF];
            EXPECT_EQ(scene.sceneKey_, OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF);
            EXPECT_LE(scene.duration_, phaseStat.endTime_ - phaseStat.startTime_);
            EXPECT_EQ(scene.astcCount_, astcTestCount);
        }
    }
}

HWTEST_F(MediaLibraryAstcPhaseUnitTest, AstcPhase_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("AstcPhase_002::Start");
    auto& mediaLibraryAstcStat = MediaLibraryAstcStat::GetInstance();
    for (int i = 0; i < 200; i++) {
        int64_t start = MediaFileUtils::UTCTimeMilliSeconds();
        mediaLibraryAstcStat.AddAstcInfo(start, OHOS::Media::GenerateScene::BACKGROUND,
            OHOS::Media::AstcGenScene::NOCHARGING_SCREENOFF);
    }
    checkPhase2Case(mediaLibraryAstcStat);
    MediaLibraryAstcStat newMediaLibraryAstcStat{};
    mediaLibraryAstcStat.WriteAstcInfoToJsonFile(mediaLibraryAstcStat.phasesStat_,
        mediaLibraryAstcStat.totalAstcCount_);
    newMediaLibraryAstcStat.TryToReadAstcInfoFromJsonFile();
    checkPhase2Case(newMediaLibraryAstcStat);

    MEDIA_INFO_LOG("AstcPhase_002::End");
}

}
}