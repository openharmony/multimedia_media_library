/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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
#define MLOG_TAG "scan_demo"

#include "accesstoken_kit.h"
#include "datashare_helper.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "medialibrary_db_const.h"
#include "medialibrary_type_const.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::Media;
using namespace OHOS::DataShare;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
namespace {
static const int UID = 5003;
static const std::string TEST_BUNDLE_NAME = "ohos";
static const int TEST_USER_ID = 0;

Security::AccessToken::PermissionDef g_infoManagerTestPermDef1 = {
    .permissionName = "ohos.permission.READ_MEDIA",
    .bundleName = "ohos.acts.multimedia.mediaLibrary",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "READ_MEDIA",
    .descriptionId = 1
};

Security::AccessToken::PermissionDef g_infoManagerTestPermDef2 = {
    .permissionName = "ohos.permission.WRITE_MEDIA",
    .bundleName = "ohos.acts.multimedia.mediaLibrary",
    .grantMode = 1,
    .availableLevel = APL_NORMAL,
    .label = "label",
    .labelId = 1,
    .description = "WRITE_MEDIA",
    .descriptionId = 1
};

PermissionStateFull g_infoManagerTestState1 = {
    .permissionName = "ohos.permission.READ_MEDIA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

PermissionStateFull g_infoManagerTestState2 = {
    .permissionName = "ohos.permission.WRITE_MEDIA",
    .isGeneral = true,
    .resDeviceID = {"local"},
    .grantStatus = {PermissionState::PERMISSION_GRANTED},
    .grantFlags = {1}
};

HapInfoParams g_infoManagerTestInfoParms = {
    .userID = 1,
    .bundleName = "accesstoken_test",
    .instIndex = 0,
    .appIDDesc = "testtesttesttest"
};

HapPolicyParams g_infoManagerTestPolicyPrams = {
    .apl = APL_NORMAL,
    .domain = "test.domain",
    .permList = {g_infoManagerTestPermDef1, g_infoManagerTestPermDef2},
    .permStateList = {g_infoManagerTestState1, g_infoManagerTestState2}
};
}
}
}

static void SetUp()
{
    HapInfoParams info = {
        .userID = TEST_USER_ID,
        .bundleName = TEST_BUNDLE_NAME,
        .instIndex = 0,
        .appIDDesc = "appIDDesc",
    };

    HapPolicyParams policy = {
        .apl = APL_NORMAL,
        .domain = "domain"
    };

    AccessTokenKit::AllocHapToken(info, policy);
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);
    (void)remove("/data/token.json");
}

static std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper(int32_t systemAbilityId)
{
    MEDIA_INFO_LOG("CreateDataShareHelper::CreateFileExtHelper ");
    auto saManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saManager == nullptr) {
        MEDIA_INFO_LOG("CreateFileExtHelper Get system ability mgr failed.");
        return nullptr;
    }
    auto remoteObj = saManager->GetSystemAbility(systemAbilityId);
    while (remoteObj == nullptr) {
        MEDIA_INFO_LOG("CreateDataShareHelper GetSystemAbility Service Failed.");
        return nullptr;
    }
    return DataShare::DataShareHelper::Creator(remoteObj, MEDIALIBRARY_DATA_URI);
}

static void SetPermission()
{
    SetUp();
    AccessTokenID tokenID = AccessTokenKit::GetHapTokenID(g_infoManagerTestInfoParms.userID,
                                                          g_infoManagerTestInfoParms.bundleName,
                                                          g_infoManagerTestInfoParms.instIndex);
    AccessTokenKit::DeleteToken(tokenID);

    tokenID = AccessTokenKit::GetHapTokenID(TEST_USER_ID, TEST_BUNDLE_NAME, 0);
    AccessTokenKit::DeleteToken(tokenID);
    AccessTokenIDEx tokenIdEx = {0};
    tokenIdEx = AccessTokenKit::AllocHapToken(g_infoManagerTestInfoParms, g_infoManagerTestPolicyPrams);
    SetSelfTokenID(tokenIdEx.tokenIdExStruct.tokenID);
}

/*
 * Feature: MediaScanner
 * Function: Strat scanner
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 */
int32_t main()
{
    SetPermission();
    auto mediaDataShareHelper = CreateDataShareHelper(UID);
    if (mediaDataShareHelper == nullptr) {
        MEDIA_ERR_LOG("mediaDataShareHelper fail");
        return 0;
    }
    Uri scanUri(MEDIALIBRARY_DATA_URI + "/" + MEDIA_BOARDCASTOPRN);
    DataShareValuesBucket valuesBucket;
    valuesBucket.PutString(MEDIA_DATA_DB_FILE_PATH, ROOT_MEDIA_DIR);
    mediaDataShareHelper->Insert(scanUri, valuesBucket);
    return 0;
}
