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

#include "medialibrary_mock_tocken.h"

using namespace std;
namespace OHOS::Media {
using namespace testing::ext;

uint64_t MediaLibraryMockTokenUtils::shellToken_ = 0;
std::mutex MediaLibraryMockTokenUtils::lockShellToken;

void MediaLibraryMockTokenUtils::RestoreShellToken(uint64_t shellTokenId)
{
    lock_guard<std::mutex> guard(lockShellToken);
    shellToken_ = shellTokenId;
}

void MediaLibraryMockTokenUtils::ResetToken()
{
    lock_guard<std::mutex> guard(lockShellToken);
    shellToken_ = 0;
}

uint64_t MediaLibraryMockTokenUtils::GetShellToken()
{
    lock_guard<std::mutex> guard(lockShellToken);
    return shellToken_;
}

AccessTokenIDEx MediaLibraryMockTokenUtils::AllocTestHapToken(const HapInfoParams &hapInfo, HapPolicyParams &hapPolicy)
{
    AccessTokenIDEx tokenIdEx = {0};
    uint64_t selfTokenId = GetSelfTokenID();
    for (auto &permissionStateFull : hapPolicy.permStateList) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(permissionStateFull.permissionName, permDefResult) != RET_SUCCESS) {
            continue;
        }
        if (permDefResult.availableLevel > hapPolicy.apl) {
            hapPolicy.aclRequestedList.emplace_back(permissionStateFull.permissionName);
        }
    }
    if (MediaLibraryMockTokenUtils::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
    } else {
        // set sh token for self
        MediaLibraryMockNativeToken mock("foundation");
        AccessTokenKit::InitHapToken(hapInfo, hapPolicy, tokenIdEx);
        // restore
        EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    }
    return tokenIdEx;
}

int32_t MediaLibraryMockTokenUtils::DeleteTestHapToken(AccessTokenID tokenID)
{
    uint64_t selfTokenId = GetSelfTokenID();
    if (MediaLibraryMockTokenUtils::GetNativeTokenIdFromProcess("foundation") == selfTokenId) {
        return AccessTokenKit::DeleteToken(tokenID);
    }
    // set sh token for self
    MediaLibraryMockNativeToken mock("foundation");
    int32_t ret = AccessTokenKit::DeleteToken(tokenID);
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return ret;
}

AccessTokenID MediaLibraryMockTokenUtils::GetNativeTokenIdFromProcess(const std::string &process)
{
    uint64_t selfTokenId = GetSelfTokenID();
    EXPECT_EQ(0, SetSelfTokenID(MediaLibraryMockTokenUtils::GetShellToken()));  // set shell token

    std::string dumpInfo;
    AtmToolsParamInfo info;
    info.processName = process;
    AccessTokenKit::DumpTokenInfo(info, dumpInfo);
    size_t pos = dumpInfo.find("\"tokenID\": ");
    if (pos == std::string::npos) {
        return 0;
    }
    pos += std::string("\"tokenID\": ").length();
    std::string numStr;
    while (pos < dumpInfo.length() && std::isdigit(dumpInfo[pos])) {
        numStr += dumpInfo[pos];
        ++pos;
    }
    // restore
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));

    std::istringstream iss(numStr);
    AccessTokenID tokenID;
    iss >> tokenID;
    return tokenID;
}

// need call by native process
AccessTokenIDEx MediaLibraryMockTokenUtils::GetHapTokenIdFromBundle(int32_t userID,
    const std::string &bundleName, int32_t instIndex)
{
    uint64_t selfTokenId = GetSelfTokenID();
    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(static_cast<AccessTokenID>(selfTokenId));
    if (type != TOKEN_NATIVE) {
        AccessTokenID tokenId1 = GetNativeTokenIdFromProcess("privacy_service");
        EXPECT_EQ(0, SetSelfTokenID(tokenId1));
    }
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(userID, bundleName, instIndex);
    EXPECT_EQ(0, SetSelfTokenID(selfTokenId));
    return tokenIdEx;
}

int32_t MediaLibraryMockTokenUtils::GrantPermissionByTest(AccessTokenID tokenID,
    const std::string &permission, uint32_t flag)
{
    std::vector<std::string> reqPerm;
    reqPerm.emplace_back("ohos.permission.GRANT_SENSITIVE_PERMISSIONS");
    MediaLibraryMockHapToken mock("AccessTokenTestGrant", reqPerm);
    return AccessTokenKit::GrantPermission(tokenID, permission, flag);
}

MediaLibraryMockNativeToken::MediaLibraryMockNativeToken(const std::string &process)
{
    shellToken = GetSelfTokenID();
    uint64_t tokenId = MediaLibraryMockTokenUtils::GetNativeTokenIdFromProcess(process);
    SetSelfTokenID(tokenId);
}

MediaLibraryMockNativeToken::~MediaLibraryMockNativeToken()
{
    SetSelfTokenID(shellToken);
}

MediaLibraryMockHapToken::MediaLibraryMockHapToken(const std::string &bundle,
    const std::vector<std::string> &reqPerm, bool isSystemApp)
{
    // get shell token befor mock
    shellToken = GetSelfTokenID();
    HapInfoParams infoParams = {
        .userID = 0,
        .bundleName = bundle,
        .instIndex = 0,
        .appIDDesc = "AccessTokenTestAppID",
        .apiVersion = MediaLibraryMockTokenUtils::DEFAULT_API_VERSION,
        .isSystemApp = isSystemApp,
        .appDistributionType = "",
    };

    HapPolicyParams policyParams = {
        .apl = APL_NORMAL,
        .domain = "accesstoken_test_domain",
    };

    for (size_t i = 0; i < reqPerm.size(); ++i) {
        PermissionDef permDefResult;
        if (AccessTokenKit::GetDefPermission(reqPerm[i], permDefResult) != RET_SUCCESS) {
            continue;
        }
        PermissionStateFull permState = {.permissionName = reqPerm[i],
            .isGeneral = true,
            .resDeviceID = {"local3"},
            .grantStatus = {PermissionState::PERMISSION_DENIED},
            .grantFlags = {PermissionFlag::PERMISSION_DEFAULT_FLAG}};
        policyParams.permStateList.emplace_back(permState);
        if (permDefResult.availableLevel > policyParams.apl) {
            policyParams.aclRequestedList.emplace_back(reqPerm[i]);
        }
    }
    //  mock hap token
    AccessTokenIDEx tokenIdEx = MediaLibraryMockTokenUtils::AllocTestHapToken(infoParams, policyParams);
    mockToken_ = tokenIdEx.tokenIdExStruct.tokenID;
    EXPECT_NE(mockToken_, INVALID_TOKENID);
    // reset token
    EXPECT_EQ(0, SetSelfTokenID(tokenIdEx.tokenIDEx));
}

MediaLibraryMockHapToken::~MediaLibraryMockHapToken()
{
    if (mockToken_ != INVALID_TOKENID) {
        EXPECT_EQ(0, MediaLibraryMockTokenUtils::DeleteTestHapToken(mockToken_));
    }
    EXPECT_EQ(0, SetSelfTokenID(shellToken));
}
}