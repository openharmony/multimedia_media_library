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

#define MLOG_TAG "MediaCloudSync"

#include "cloud_media_dao_utils_extended_test.h"

#include "media_log.h"
#include "cloud_media_dao_utils.h"
#include "cloud_media_photos_dao.h"
#include "cloud_mdkrecord_photos_vo.h"
#include "photos_po.h"
#include "cloud_media_define.h"

namespace OHOS::Media::CloudSync {
using namespace testing::ext;

void CloudMediaDaoUtilsExtendedTest::SetUpTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaDaoUtilsExtendedTest::SetUpTestCase");
}

void CloudMediaDaoUtilsExtendedTest::TearDownTestCase(void)
{
    MEDIA_INFO_LOG("start CloudMediaDaoUtilsExtendedTest::TearDownTestCase");
}

void CloudMediaDaoUtilsExtendedTest::SetUp()
{
    MEDIA_INFO_LOG("setup");
}

void CloudMediaDaoUtilsExtendedTest::TearDown(void) {}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithBraces, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test{path}/file{name}");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test{path}/file{name}");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithBraces, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test{path}/file{name}"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test{path}/file{name};");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithAtSign, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test@path/file@name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithAtSign, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test@path/file@name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithAtSign, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test@path/file@name";
    pathInfo.storagePath = "/storage/lake/test@path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithAtSign, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test@path/file@name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test@path/file@name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithAtSign, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test@path/file@name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test@path/file@name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithAtSign, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test@path/file@name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test@path/file@name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithHash, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test#path/file#name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithHash, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test#path/file#name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithHash, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test#path/file#name";
    pathInfo.storagePath = "/storage/lake/test#path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithHash, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test#path/file#name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test#path/file#name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithHash, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test#path/file#name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test#path/file#name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithHash, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test#path/file#name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test#path/file#name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithPercent, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test%path/file%name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithPercent, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test%path/file%name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithPercent, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test%path/file%name";
    pathInfo.storagePath = "/storage/lake/test%path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithPercent, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test%path/file%name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test%path/file%name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithPercent, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test%path/file%name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test%path/file%name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithPercent, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test%path/file%name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test%path/file%name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithAmpersand, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test&path/file&name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithAmpersand, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test&path/file&name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithAmpersand, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test&path/file&name";
    pathInfo.storagePath = "/storage/lake/test&path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithAmpersand, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test&path/file&name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test&path/file&name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithAmpersand, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test&path/file&name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test&path/file&name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithAmpersand, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test&path/file&name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test&path/file&name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithAsterisk, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test*path/file*name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithAsterisk, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test*path/file*name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithAsterisk, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test*path/file*name";
    pathInfo.storagePath = "/storage/lake/test*path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithAsterisk, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test*path/file*name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test*path/file*name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithAsterisk, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test*path/file*name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test*path/file*name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithAsterisk, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test*path/file*name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test*path/file*name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithPlus, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test+path/file+name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithPlus, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test+path/file+name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithPlus, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test+path/file+name";
    pathInfo.storagePath = "/storage/lake/test+path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithPlus, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test+path/file+name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test+path/file+name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithPlus, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test+path/file+name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test+path/file+name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithPlus, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test+path/file+name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test+path/file+name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithEquals, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test=path/file=name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithEquals, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test=path/file=name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithEquals, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test=path/file=name";
    pathInfo.storagePath = "/storage/lake/test=path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithEquals, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test=path/file=name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test=path/file=name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithEquals, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test=path/file=name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test=path/file=name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithEquals, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test=path/file=name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test=path/file=name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithQuestion, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test?path/file?name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithQuestion, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test?path/file?name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithQuestion, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test?path/file?name";
    pathInfo.storagePath = "/storage/lake/test?path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithQuestion, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test?path/file?name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test?path/file?name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithQuestion, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test?path/file?name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test?path/file?name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithQuestion, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test?path/file?name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test?path/file?name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithExclamation, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test!path/file!name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithExclamation, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test!path/file!name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithExclamation, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test!path/file!name";
    pathInfo.storagePath = "/storage/lake/test!path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithExclamation, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test!path/file!name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test!path/file!name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithExclamation, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test!path/file!name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test!path/file!name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithExclamation, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test!path/file!name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test!path/file!name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithTilde, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test~path/file~name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithTilde, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test~path/file~name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithTilde, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test~path/file~name";
    pathInfo.storagePath = "/storage/lake/test~path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithTilde, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test~path/file~name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test~path/file~name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithTilde, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test~path/file~name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test~path/file~name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithTilde, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test~path/file~name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test~path/file~name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithBacktick, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test`path/file`name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithBacktick, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test`path/file`name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithBacktick, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test`path/file`name";
    pathInfo.storagePath = "/storage/lake/test`path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithBacktick, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test`path/file`name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test`path/file`name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithBacktick, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test`path/file`name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test`path/file`name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithBacktick, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test`path/file`name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test`path/file`name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithPipe, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test|path/file|name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithPipe, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test|path/file|name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithPipe, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test|path/file|name";
    pathInfo.storagePath = "/storage/lake/test|path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithPipe, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test|path/file|name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test|path/file|name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithPipe, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test|path/file|name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test|path/file|name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithPipe, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test|path/file|name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test|path/file|name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithSemicolon, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test;path/file;name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithSemicolon, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test;path/file;name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithSemicolon, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test;path/file;name";
    pathInfo.storagePath = "/storage/lake/test;path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithSemicolon, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test;path/file;name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test;path/file;name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithSemicolon, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test;path/file;name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test;path/file;name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithSemicolon, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test;path/file;name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test;path/file;name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithColon, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test:path/file:name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithColon, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test:path/file:name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithColon, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test:path/file:name";
    pathInfo.storagePath = "/storage/lake/test:path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithColon, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test:path/file:name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test:path/file:name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithColon, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test:path/file:name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test:path/file:name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithColon, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test:path/file:name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test:path/file:name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithComma, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test,path/file,name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithComma, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test,path/file,name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithComma, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test,path/file,name";
    pathInfo.storagePath = "/storage/lake/test,path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithComma, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test,path/file,name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test,path/file,name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithComma, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test,path/file,name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test,path/file,name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithComma, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test,path/file,name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test,path/file,name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithLessThan, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test<path/file<name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithLessThan, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test<path/file<name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithLessThan, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test<path/file<name";
    pathInfo.storagePath = "/storage/lake/test<path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithLessThan, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test<path/file<name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test<path/file<name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithLessThan, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test<path/file<name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test<path/file<name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithLessThan, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test<path/file<name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test<path/file<name;");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPhotosVo_PathWithGreaterThan, TestSize.Level1)
{
    CloudMdkRecordPhotosVo photosVo;
    photosVo.fileSourceType = 0;
    photosVo.data = "/storage/cloud/files/test>path/file>name";
    std::string localPath;
    int32_t userId = 100;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPhotosVo(photosVo, localPath, userId);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathByPullData_PathWithGreaterThan, TestSize.Level1)
{
    CloudMediaPullDataDto pullData;
    ORM::PhotosPo photosPo;
    photosPo.fileSourceType = 0;
    photosPo.data = "/test>path/file>name";
    pullData.localPhotosPoOp = photosPo;
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathByPullData(pullData, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, GetLocalPathWithAnco_PathWithGreaterThan, TestSize.Level1)
{
    CloudMediaDaoUtils::PathInfo pathInfo;
    pathInfo.fileSourceType = 0;
    pathInfo.filePath = "/test>path/file>name";
    pathInfo.storagePath = "/storage/lake/test>path";
    std::string localPath;
    int32_t result = CloudMediaDaoUtils::GetLocalPathWithAnco(pathInfo, localPath);
    EXPECT_EQ(result, E_OK);
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithCommaAndQuote_PathWithGreaterThan, TestSize.Level1)
{
    std::vector<std::string> values;
    values.emplace_back("/test>path/file>name");
    std::string result = CloudMediaDaoUtils::ToStringWithCommaAndQuote(values);
    EXPECT_EQ(result, "'/test>path/file>name'");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, ToStringWithComma_PathWithGreaterThan, TestSize.Level1)
{
    std::vector<std::string> fileIds;
    fileIds.emplace_back("/test>path/file>name");
    std::string result = CloudMediaDaoUtils::ToStringWithComma(fileIds);
    EXPECT_EQ(result, "/test>path/file>name");
}

HWTEST_F(CloudMediaDaoUtilsExtendedTest, FillParams_PathWithGreaterThan, TestSize.Level1)
{
    std::string sql = "SELECT name FROM Stu WHERE path = {0};";
    std::vector<std::string> bindArgs = {"/test>path/file>name"};
    std::string result = CloudMediaDaoUtils::FillParams(sql, bindArgs);
    EXPECT_EQ(result, "SELECT name FROM Stu WHERE path = /test>path/file>name;");
}
}
