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

#ifndef MEDIALIBRARY_MOCK_TOCKEN_H
#define MEDIALIBRARY_MOCK_TOCKEN_H

#include <string>
#include <mutex>
#include <sstream>

#include "gtest/gtest.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace Media {

using namespace OHOS::Security::AccessToken;

class MediaLibraryMockNativeToken {
public:
    explicit MediaLibraryMockNativeToken(const std::string &process);
    ~MediaLibraryMockNativeToken();

private:
    uint64_t shellToken;
};

class MediaLibraryMockHapToken {
public:
    explicit MediaLibraryMockHapToken(const std::string &bundle, const std::vector<std::string> &reqPerm,
        bool isSystemApp = true);
    ~MediaLibraryMockHapToken();

private:
    uint64_t shellToken;
    uint64_t mockToken_;
};
class MediaLibraryMockTokenUtils {
public:
    static constexpr int32_t DEFAULT_API_VERSION = 12;
    static void RestoreShellToken(uint64_t shellTokenId);
    static void ResetToken();
    static uint64_t GetShellToken();

    static AccessTokenIDEx AllocTestHapToken(const HapInfoParams &hapInfo, HapPolicyParams &hapPolicy);
    static int32_t DeleteTestHapToken(AccessTokenID tokenID);
    static AccessTokenID GetNativeTokenIdFromProcess(const std::string &process);
    static AccessTokenIDEx GetHapTokenIdFromBundle(int32_t userID, const std::string &bundleName, int32_t instIndex);
    static int32_t GrantPermissionByTest(AccessTokenID tokenID, const std::string &permission, uint32_t flag);

private:
    static uint64_t shellToken_;
    static std::mutex lockShellToken;
};
}
}
#endif  // MEDIALIBRARY_MOCK_TOCKEN_H