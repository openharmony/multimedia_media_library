/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#define MLOG_TAG "MediaPermissionCheckTest"

#include "media_permission_check_test.h"

#include "media_log.h"
#include "media_permission_check.h"
#include "medialibrary_errno.h"
#include "media_file_utils.h"
#include "medialibrary_business_code.h"
#include "get_self_permissions.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace Media {
extern bool (*isCalledBySelfPtr)();
std::unordered_map<uint32_t,
    std::vector<std::vector<PermissionType>>> MediaPermissionCheckTest::originalBusinessCodeToPermissions;

void MediaPermissionCheckTest::SetUpTestCase(void)
{
    originalBusinessCodeToPermissions = PermissionCheck::businessCodeToPermissions;
    std::unordered_map<uint32_t, std::vector<std::vector<PermissionType>>> testMap = {
        {1, {{PRIVATE_PERM}}},
        {2, {{CLOUDFILE_SYNC}}},
        {3, {{READ_PERM}}},
        {4, {{WRITE_PERM} }},
        {5, {{SYSTEMAPI_PERM}, {}}},
        {6, {{}, {SYSTEMAPI_PERM}}},
        {7, {}},
        {8, {{PRIVATE_PERM, CLOUDFILE_SYNC, READ_PERM, WRITE_PERM}}},
        {0, {{READ_PERM}, {WRITE_PERM}}},
        {static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN), { {READ_PERM, WRITE_PERM} }}, //openfile api
    };
    PermissionCheck::businessCodeToPermissions = testMap;
}

void MediaPermissionCheckTest::TearDownTestCase(void)
{
    PermissionCheck::businessCodeToPermissions = originalBusinessCodeToPermissions;
}

bool MockIsCalledBySelf()
{
    return E_FAIL;
}

pid_t mockGetCallingUid()
{
    return 123456;
}

pid_t mockGetCallingUidShell()
{
    return 2000;
}

void MediaPermissionCheckTest::SetUp(void)
{
    isCalledBySelfPtr = MockIsCalledBySelf;
    getCallingUidPtr = mockGetCallingUid;
}

void MediaPermissionCheckTest::TearDown(void)
{
    isCalledBySelfPtr = MediaFileUtils::IsCalledBySelf;
    getCallingUidPtr = IPCSkeleton::GetCallingUid;
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_001, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_001 begin");
    vector<string> perms;
    perms.push_back("ohos.permission.READ_MEDIA");
    perms.push_back("ohos.permission.WRITE_MEDIA");
    perms.push_back("ohos.permission.MANAGE_PRIVATE_PHOTOS");
    perms.push_back("ohos.permission.CLOUDFILE_SYNC_MANAGER");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaPermissionCheckTest", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_001 tokenId=%{public}llu", static_cast<unsigned long long>(tokenId));
    PermissionHeaderReq data;
    uint32_t businessCode = 1;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_001 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_002, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_002 begin");
    PermissionHeaderReq data;
    uint32_t businessCode = 2;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_002 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_005, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_005 begin");
    PermissionHeaderReq data;
    uint32_t businessCode = 5;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_005 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_006, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_006 begin");
    PermissionHeaderReq data;
    uint32_t businessCode = 6;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_006 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_007, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_007 begin");
    PermissionHeaderReq data;
    uint32_t businessCode = 7;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_007 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_011, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_011 begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::FILE_ID_KEY, "1"},
        {PermissionHeaderReq::URI_TYPE_KEY, "2"},
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 100);
    uint32_t businessCode = 3;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    businessCode = 4;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_011 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_012, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_012 begin");
    PermissionHeaderReq data;
    //invalid api code
    uint32_t businessCode = 1000000;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_012 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_013, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_013 begin");
    // invalid map
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::FILE_ID_KEY, "1"},
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, -1);
    uint32_t businessCode = 3;
    isCalledBySelfPtr = MediaFileUtils::IsCalledBySelf;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_013 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_014, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_014 begin");
    vector<string> perms;
    perms.push_back("ohos.permission.SHORT_TERM_WRITE_IMAGEVIDEO");
    uint64_t tokenId = 0;
    PermissionUtilsUnitTest::SetAccessTokenPermission("MediaPermissionCheckTest_014", perms, tokenId);
    ASSERT_TRUE(tokenId != 0);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_014 tokenId=%{public}llu", static_cast<unsigned long long>(tokenId));
    PermissionHeaderReq data;
    uint32_t businessCode = 1;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    businessCode = 2;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    businessCode = 4;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_014 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_015, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_015 begin");
    getCallingUidPtr = IPCSkeleton::GetCallingUid;
    PermissionHeaderReq data;
    uint32_t businessCode = 3;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    isCalledBySelfPtr = MediaFileUtils::IsCalledBySelf;
    businessCode = 3;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_015 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_016, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_016 begin");
    getCallingUidPtr = IPCSkeleton::GetCallingUid;
    PermissionHeaderReq data;
    uint32_t businessCode = 4;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    isCalledBySelfPtr = MediaFileUtils::IsCalledBySelf;
    businessCode = 4;
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_SUCCESS);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_016 end");
}


HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_OPENFILE, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::FILE_ID_KEY, "1"},
        {PermissionHeaderReq::URI_TYPE_KEY, "2"},
        {PermissionHeaderReq::OPEN_URI_KEY, "file://media/Photo/picture/?file_id=1"},
        {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 1);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN);
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_OPENFILE_2, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_2 begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::OPEN_URI_KEY,
            "file://media/Photo/6/1/1.jpg?operation=thumbnail&width=720&height=720&path=/storage/cloud/files/Photo/1/"
            "1.jpg"},
        {PermissionHeaderReq::OPEN_MODE_KEY, "r"}
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 1);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN);
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_2 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_OPENFILE_3, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_3 begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::OPEN_URI_KEY, "file://media/Photo/picture/?file_id=1"},
        {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 1);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN);
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_3 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_OPENFILE_4, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_4 begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::OPEN_URI_KEY, "file:://media/photo_operation/query"},
        {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 1);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN);
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_4 end");
}

HWTEST_F(MediaPermissionCheckTest, MediaPermissionCheckTest_OPENFILE_5, TestSize.Level0)
{
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_5 begin");
    std::unordered_map<std::string, std::string> headerMap = {
        {PermissionHeaderReq::OPEN_URI_KEY,
            "file://media/Photo/6/1/1.jpg?operation=astc&width=720&height=720&path=/storage/cloud/files/Photo/1/1.jpg"},
        {PermissionHeaderReq::OPEN_MODE_KEY, "rw"}
    };
    PermissionHeaderReq data = PermissionHeaderReq::convertToPermissionHeaderReq(headerMap, 1);
    uint32_t businessCode = static_cast<uint32_t>(MediaLibraryBusinessCode::PAH_OPEN);
    EXPECT_EQ(PermissionCheck::VerifyPermissions(businessCode, data), E_PERMISSION_DENIED);
    MEDIA_INFO_LOG("MediaPermissionCheckTest_OPENFILE_5 end");
}

} // namespace Media
} // namespace OHOS
