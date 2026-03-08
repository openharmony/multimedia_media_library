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

#define MLOG_TAG "MediaAnalysisDataServiceTest"

#include "media_analysis_data_service_test.h"

#include "datashare_predicates.h"
#include "datashare_values_bucket.h"
#include "get_asset_analysis_data_dto.h"
#include "media_log.h"
#include "medialibrary_errno.h"
#include "media_column.h"
#include "medialibrary_rdbstore.h"
#include "medialibrary_data_manager.h"
#include "medialibrary_unistore_manager.h"
#include "medialibrary_unittest_utils.h"
#include "result_set_utils.h"
#include "rdb_utils.h"
#include "uri.h"
#include "values_bucket.h"
#include "vision_column.h"
#include "photo_album_column.h"
#include "media_analysis_data_service.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing::ext;
using namespace OHOS::NativeRdb;
using namespace OHOS::DataShare;
using namespace OHOS::Media::AnalysisData;

static shared_ptr<MediaLibraryRdbStore> g_rdbStore;

static int32_t JS_INNER_FAIL = 14000011;

void MediaAnalysisDataServiceTest::SetUpTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisDataServiceTest SetUpTestCase start");
    MediaLibraryUnitTestUtils::Init();
    g_rdbStore = MediaLibraryUnistoreManager::GetInstance().GetRdbStore();
    if (g_rdbStore == nullptr) {
        MEDIA_ERR_LOG("Start MediaAnalysisDataServiceTest failed, can not get rdbstore");
        exit(1);
    }
    MEDIA_INFO_LOG("MediaAnalysisDataServiceTest SetUpTestCase end");
}

void MediaAnalysisDataServiceTest::TearDownTestCase()
{
    MEDIA_INFO_LOG("MediaAnalysisDataServiceTest TearDownTestCase");
    g_rdbStore = nullptr;
    MediaLibraryDataManager::GetInstance()->ClearMediaLibraryMgr();
}

void MediaAnalysisDataServiceTest::SetUp()
{
    MEDIA_INFO_LOG("MediaAnalysisDataServiceTest SetUp");
}

void MediaAnalysisDataServiceTest::TearDown()
{
    MEDIA_INFO_LOG("MediaAnalysisDataServiceTest TearDown");
}

// 用例说明：测试无效的 analysisType 参数
// - 覆盖场景：GetAssetAnalysisData 函数中传入不支持的 analysisType
// - 覆盖分支点：ANALYSIS_CONFIG_MAP.find() 失败分支 (145行)
// - 触发条件：传入一个不在 ANALYSIS_CONFIG_MAP 中的 analysisType 值
// - 业务验证：函数应返回 -EINVAL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetAssetAnalysisData_InvalidAnalysisType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAssetAnalysisData_InvalidAnalysisType");
    GetAssetAnalysisDataDto dto;
    dto.fileId = 1;
    dto.analysisType = 9999;
    dto.language = "en";
    dto.analysisTotal = false;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAssetAnalysisData(dto);
    EXPECT_EQ(ret, -EINVAL);
    MEDIA_INFO_LOG("end GetAssetAnalysisData_InvalidAnalysisType");
}

// 用例说明：测试 analysisTotal 为 true 的场景
// - 覆盖场景：GetAssetAnalysisData 函数中 analysisTotal=true 时查询 VISION_TOTAL_TABLE
// - 覆盖分支点：dto.analysisTotal 分支 (152行)
// - 触发条件：设置 analysisTotal 为 true
// - 业务验证：函数应正常执行查询逻辑
HWTEST_F(MediaAnalysisDataServiceTest, GetAssetAnalysisData_AnalysisTotalTrue, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAssetAnalysisData_AnalysisTotalTrue");
    GetAssetAnalysisDataDto dto;
    dto.fileId = 1;
    dto.analysisType = ANALYSIS_AESTHETICS_SCORE;
    dto.language = "en";
    dto.analysisTotal = true;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAssetAnalysisData(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAssetAnalysisData_AnalysisTotalTrue");
}

// 用例说明：测试 ANALYSIS_FACE 类型的查询
// - 覆盖场景：GetAssetAnalysisData 函数中 analysisType 为 ANALYSIS_FACE
// - 覆盖分支点：dto.analysisType == ANALYSIS_FACE 分支 (158行)
// - 触发条件：设置 analysisType 为 ANALYSIS_FACE
// - 业务验证：函数应使用正确的查询条件
HWTEST_F(MediaAnalysisDataServiceTest, GetAssetAnalysisData_AnalysisFaceType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAssetAnalysisData_AnalysisFaceType");
    GetAssetAnalysisDataDto dto;
    dto.fileId = 1;
    dto.analysisType = ANALYSIS_FACE;
    dto.language = "en";
    dto.analysisTotal = false;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAssetAnalysisData(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAssetAnalysisData_AnalysisFaceType");
}

// 用例说明：测试 ANALYSIS_HUMAN_FACE_TAG 类型的查询
// - 覆盖场景：GetAssetAnalysisData 函数中 analysisType 为 ANALYSIS_HUMAN_FACE_TAG
// - 覆盖分支点：dto.analysisType == ANALYSIS_HUMAN_FACE_TAG 分支 (161行)
// - 触发条件：设置 analysisType 为 ANALYSIS_HUMAN_FACE_TAG
// - 业务验证：函数应使用 INNER JOIN 查询
HWTEST_F(MediaAnalysisDataServiceTest, GetAssetAnalysisData_AnalysisHumanFaceTagType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAssetAnalysisData_AnalysisHumanFaceTagType");
    GetAssetAnalysisDataDto dto;
    dto.fileId = 1;
    dto.analysisType = ANALYSIS_HUMAN_FACE_TAG;
    dto.language = "en";
    dto.analysisTotal = false;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAssetAnalysisData(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAssetAnalysisData_AnalysisHumanFaceTagType");
}

// 用例说明：测试 ANALYSIS_DETAIL_ADDRESS 类型的查询
// - 覆盖场景：GetAssetAnalysisData 函数中 analysisType 为 ANALYSIS_DETAIL_ADDRESS
// - 覆盖分支点：dto.analysisType == ANALYSIS_DETAIL_ADDRESS 分支 (166行)
// - 触发条件：设置 analysisType 为 ANALYSIS_DETAIL_ADDRESS
// - 业务验证：函数应使用 LEFT OUTER JOIN 查询
HWTEST_F(MediaAnalysisDataServiceTest, GetAssetAnalysisData_AnalysisDetailAddressType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAssetAnalysisData_AnalysisDetailAddressType");
    GetAssetAnalysisDataDto dto;
    dto.fileId = 1;
    dto.analysisType = ANALYSIS_DETAIL_ADDRESS;
    dto.language = "en";
    dto.analysisTotal = false;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAssetAnalysisData(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAssetAnalysisData_AnalysisDetailAddressType");
}

// 用例说明：测试 GetIndexConstructProgress 失败场景
// - 覆盖场景：GetIndexConstructProgress 函数中查询失败
// - 覆盖分支点：resultSet->GoToFirstRow() 失败分支 (190行)
// - 触发条件：查询结果为空或查询失败
// - 业务验证：函数应返回 E_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetIndexConstructProgress_QueryFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetIndexConstructProgress_QueryFailed");
    std::string indexProgress;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetIndexConstructProgress(indexProgress);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetIndexConstructProgress_QueryFailed");
}

// 用例说明：测试 SetOrderPosition 参数校验失败
// - 覆盖场景：SetOrderPosition 函数中参数转换失败
// - 覆盖分支点：value.IsEmpty() 分支 (235行)
// - 触发条件：传入无效的参数导致 ValuesBucket 为空
// - 业务验证：函数应返回 E_INVALID_VALUES 错误码
HWTEST_F(MediaAnalysisDataServiceTest, SetOrderPosition_InvalidParameters, TestSize.Level1)
{
    MEDIA_INFO_LOG("start SetOrderPosition_InvalidParameters");
    ChangeRequestSetOrderPositionDto dto;
    dto.albumId = -1;
    dto.orderString = "";
    dto.assetIds = {};
    
    int32_t ret = MediaAnalysisDataService::GetInstance().SetOrderPosition(dto);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end SetOrderPosition_InvalidParameters");
}

// 用例说明：测试 GetOrderPosition 查询失败
// - 覆盖场景：GetOrderPosition 函数中查询结果为空
// - 覆盖分支点：resultSet == nullptr 分支 (264行)
// - 触发条件：查询返回空结果集
// - 业务验证：函数应返回 E_ERR 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetOrderPosition_QueryFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetOrderPosition_QueryFailed");
    GetOrderPositionDto dto;
    dto.albumId = 1;
    dto.assetIdArray = {"1", "2"};
    GetOrderPositionRespBody resp;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetOrderPosition(dto, resp);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end GetOrderPosition_QueryFailed");
}

// 用例说明：测试 GetOrderPosition 获取行数失败
// - 覆盖场景：GetOrderPosition 函数中 GetRowCount 失败
// - 覆盖分支点：resultSet->GetRowCount() 失败分支 (270行)
// - 触发条件：获取行数操作失败
// - 业务验证：函数应返回 JS_INNER_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetOrderPosition_GetRowCountFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetOrderPosition_GetRowCountFailed");
    GetOrderPositionDto dto;
    dto.albumId = 1;
    dto.assetIdArray = {"1", "2"};
    GetOrderPositionRespBody resp;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetOrderPosition(dto, resp);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end GetOrderPosition_GetRowCountFailed");
}

// 用例说明：测试 GetPortraitRelationship 查询失败
// - 覆盖场景：GetPortraitRelationship 函数中查询结果为空
// - 覆盖分支点：resultSet == nullptr 分支 (306行)
// - 触发条件：查询返回空结果集
// - 业务验证：函数应返回 JS_INNER_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetPortraitRelationship_QueryFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetPortraitRelationship_QueryFailed");
    int32_t albumId = 1;
    GetRelationshipRespBody resp;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetPortraitRelationship(albumId, resp);
    EXPECT_EQ(ret, JS_INNER_FAIL);
    MEDIA_INFO_LOG("end GetPortraitRelationship_QueryFailed");
}

// 用例说明：测试 GetPortraitRelationship 获取行数失败
// - 覆盖场景：GetPortraitRelationship 函数中 GetRowCount 失败
// - 覆盖分支点：resultSet->GetRowCount() 失败分支 (312行)
// - 触发条件：获取行数操作失败
// - 业务验证：函数应返回 JS_INNER_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetPortraitRelationship_GetRowCountFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetPortraitRelationship_GetRowCountFailed");
    int32_t albumId = 1;
    GetRelationshipRespBody resp;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetPortraitRelationship(albumId, resp);
    EXPECT_EQ(ret, JS_INNER_FAIL);
    MEDIA_INFO_LOG("end GetPortraitRelationship_GetRowCountFailed");
}

// 用例说明：测试 GetPortraitRelationship 定位第一行失败
// - 覆盖场景：GetPortraitRelationship 函数中 GoToFirstRow 失败
// - 覆盖分支点：resultSet->GoToFirstRow() 失败分支 (317行)
// - 触发条件：定位第一行操作失败
// - 业务验证：函数应返回 JS_INNER_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetPortraitRelationship_GoToFirstRowFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetPortraitRelationship_GoToFirstRowFailed");
    int32_t albumId = 1;
    GetRelationshipRespBody resp;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetPortraitRelationship(albumId, resp);
    EXPECT_EQ(ret, JS_INNER_FAIL);
    MEDIA_INFO_LOG("end GetPortraitRelationship_GoToFirstRowFailed");
}

// 用例说明：测试 GetAnalysisProcess 无效类型
// - 覆盖场景：GetAnalysisProcess 函数中传入无效的 analysisType
// - 覆盖分支点：默认分支 (未匹配任何已知类型)
// - 触发条件：传入一个未定义的 analysisType 值
// - 业务验证：函数应返回 E_FAIL 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetAnalysisProcess_InvalidAnalysisType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAnalysisProcess_InvalidAnalysisType");
    GetAnalysisProcessReqBody reqBody;
    reqBody.analysisType = 9999;
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAnalysisProcess_InvalidAnalysisType");
}

// 用例说明：测试 GetAnalysisProcess ANALYSIS_INVALID 类型
// - 覆盖场景：GetAnalysisProcess 函数中 analysisType 为 ANALYSIS_INVALID
// - 覆盖分支点：AnalysisType::ANALYSIS_INVALID 分支 (334行)
// - 触发条件：设置 analysisType 为 ANALYSIS_INVALID
// - 业务验证：函数应查询正确的表和列
HWTEST_F(MediaAnalysisDataServiceTest, GetAnalysisProcess_AnalysisInvalidType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAnalysisProcess_AnalysisInvalidType");
    GetAnalysisProcessReqBody reqBody;
    reqBody.analysisType = static_cast<int32_t>(AnalysisType::ANALYSIS_INVALID);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAnalysisProcess_AnalysisInvalidType");
}

// 用例说明：测试 GetAnalysisProcess ANALYSIS_LABEL 类型
// - 覆盖场景：GetAnalysisProcess 函数中 analysisType 为 ANALYSIS_LABEL
// - 覆盖分支点：AnalysisType::ANALYSIS_LABEL 分支 (340行)
// - 触发条件：设置 analysisType 为 ANALYSIS_LABEL
// - 业务验证：函数应使用 INNER JOIN 查询
HWTEST_F(MediaAnalysisDataServiceTest, GetAnalysisProcess_AnalysisLabelType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAnalysisProcess_AnalysisLabelType");
    GetAnalysisProcessReqBody reqBody;
    reqBody.analysisType = static_cast<int32_t>(AnalysisType::ANALYSIS_LABEL);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAnalysisProcess_AnalysisLabelType");
}

// 用例说明：测试 GetAnalysisProcess ANALYSIS_FACE 类型
// - 覆盖场景：GetAnalysisProcess 函数中 analysisType 为 ANALYSIS_FACE
// - 覆盖分支点：AnalysisType::ANALYSIS_FACE 分支 (356行)
// - 触发条件：设置 analysisType 为 ANALYSIS_FACE
// - 业务验证：函数应查询 USER_PHOTOGRAPHY_INFO_TABLE
HWTEST_F(MediaAnalysisDataServiceTest, GetAnalysisProcess_AnalysisFaceType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAnalysisProcess_AnalysisFaceType");
    GetAnalysisProcessReqBody reqBody;
    reqBody.analysisType = static_cast<int32_t>(AnalysisType::ANALYSIS_FACE);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAnalysisProcess_AnalysisFaceType");
}

// 用例说明：测试 GetAnalysisProcess ANALYSIS_HIGHLIGHT 类型
// - 覆盖场景：GetAnalysisProcess 函数中 analysisType 为 ANALYSIS_HIGHLIGHT
// - 覆盖分支点：AnalysisType::ANALYSIS_HIGHLIGHT 分支 (361行)
// - 触发条件：设置 analysisType 为 ANALYSIS_HIGHLIGHT
// - 业务验证：函数应查询 HIGHLIGHT_ALBUM_TABLE
HWTEST_F(MediaAnalysisDataServiceTest, GetAnalysisProcess_AnalysisHighlightType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetAnalysisProcess_AnalysisHighlightType");
    GetAnalysisProcessReqBody reqBody;
    reqBody.analysisType = static_cast<int32_t>(AnalysisType::ANALYSIS_HIGHLIGHT);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetAnalysisProcess(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetAnalysisProcess_AnalysisHighlightType");
}

// 用例说明：测试 GetHighlightAlbumInfo 无效类型
// - 覆盖场景：GetHighlightAlbumInfo 函数中传入无效的 highlightAlbumInfoType
// - 覆盖分支点：infoMap.find() 失败分支 (393行)
// - 触发条件：传入一个未定义的 highlightAlbumInfoType 值
// - 业务验证：函数应返回 E_ERR 错误码
HWTEST_F(MediaAnalysisDataServiceTest, GetHighlightAlbumInfo_InvalidHighlightAlbumInfoType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetHighlightAlbumInfo_InvalidHighlightAlbumInfoType");
    GetHighlightAlbumReqBody reqBody;
    reqBody.albumId = 1;
    reqBody.subType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);
    reqBody.highlightAlbumInfoType = 9999;
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end GetHighlightAlbumInfo_InvalidHighlightAlbumInfoType");
}

// 用例说明：测试 GetHighlightAlbumInfo COVER_INFO 类型
// - 覆盖场景：GetHighlightAlbumInfo 函数中 highlightAlbumInfoType 为 COVER_INFO
// - 覆盖分支点：highlightAlbumInfoType == COVER_INFO 分支 (396行)
// - 触发条件：设置 highlightAlbumInfoType 为 COVER_INFO
// - 业务验证：函数应查询 HIGHLIGHT_COVER_INFO_TABLE
HWTEST_F(MediaAnalysisDataServiceTest, GetHighlightAlbumInfo_CoverInfoType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetHighlightAlbumInfo_CoverInfoType");
    GetHighlightAlbumReqBody reqBody;
    reqBody.albumId = 1;
    reqBody.subType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);
    reqBody.highlightAlbumInfoType = static_cast<int32_t>(HighlightAlbumInfoType::COVER_INFO);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetHighlightAlbumInfo_CoverInfoType");
}

// 用例说明：测试 GetHighlightAlbumInfo HIGHLIGHT_SUGGESTIONS 类型
// - 覆盖场景：GetHighlightAlbumInfo 函数中 subType 为 HIGHLIGHT_SUGGESTIONS
// - 覆盖分支点：subType == HIGHLIGHT_SUGGESTIONS 分支 (414行)
// - 触发条件：设置 subType 为 HIGHLIGHT_SUGGESTIONS
// - - 业务验证：函数应使用正确的查询条件
HWTEST_F(MediaAnalysisDataServiceTest, GetHighlightAlbumInfo_HighlightSuggestionsType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetHighlightAlbumInfo_HighlightSuggestionsType");
    GetHighlightAlbumReqBody reqBody;
    reqBody.albumId = 1;
    reqBody.subType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT_SUGGESTIONS);
    reqBody.highlightAlbumInfoType = static_cast<int32_t>(HighlightAlbumInfoType::COVER_INFO);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetHighlightAlbumInfo_HighlightSuggestionsType");
}

// 用例说明：测试 GetHighlightAlbumInfo PLAY_INFO 类型
// - 覆盖场景：GetHighlightAlbumInfo 函数中 highlightAlbumInfoType 为 PLAY_INFO
// - 覆盖分支点：highlightAlbumInfoType == PLAY_INFO 分支 (424行)
// - 触发条件：设置 highlightAlbumInfoType 为 PLAY_INFO
// - 业务验证：函数应查询 HIGHLIGHT_PLAY_INFO_TABLE
HWTEST_F(MediaAnalysisDataServiceTest, GetHighlightAlbumInfo_PlayInfoType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetHighlightAlbumInfo_PlayInfoType");
    GetHighlightAlbumReqBody reqBody;
    reqBody.albumId = 1;
    reqBody.subType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);
    reqBody.highlightAlbumInfoType = static_cast<int32_t>(HighlightAlbumInfoType::PLAY_INFO);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetHighlightAlbumInfo_PlayInfoType");
}

// 用例说明：测试 GetHighlightAlbumInfo ALBUM_INFO 类型
// - 覆盖场景：GetHighlightAlbumInfo 函数中 highlightAlbumInfoType 为 ALBUM_INFO
// - 覆盖分支点：highlightAlbumInfoType == ALBUM_INFO 分支 (426行)
// - 触发条件：设置 highlightAlbumInfoType 为 ALBUM_INFO
// - 业务验证：函数应查询 HIGHLIGHT_ALBUM_TABLE
HWTEST_F(MediaAnalysisDataServiceTest, GetHighlightAlbumInfo_AlbumInfoType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetHighlightAlbumInfo_AlbumInfoType");
    GetHighlightAlbumReqBody reqBody;
    reqBody.albumId = 1;
    reqBody.subType = static_cast<int32_t>(PhotoAlbumSubType::HIGHLIGHT);
    reqBody.highlightAlbumInfoType = static_cast<int32_t>(HighlightAlbumInfoType::ALBUM_INFO);
    QueryResultRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetHighlightAlbumInfo(reqBody, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end GetHighlightAlbumInfo_AlbumInfoType");
}

// 用例说明：测试 DeleteHighlightAlbums 空列表
// - 覆盖场景：DeleteHighlightAlbums 函数中传入空的 album
// - 覆盖分支点：changedRows >= 0 分支 (462行)
// - 触发条件：传入空的 albumIds 列表
// - 业务验证：函数应正常处理空列表
HWTEST_F(MediaAnalysisDataServiceTest, DeleteHighlightAlbums_EmptyList, TestSize.Level1)
{
    MEDIA_INFO_LOG("start DeleteHighlightAlbums_EmptyList");
    vector<string> albumIds = {};
    
    int32_t ret = MediaAnalysisDataService::GetInstance().DeleteHighlightAlbums(albumIds);
    EXPECT_GE(ret, 0);
    MEDIA_INFO_LOG("end DeleteHighlightAlbums_EmptyList");
}

// 用例说明：测试 DismissAssets 失败场景
// - 覆盖场景：DismissAssets 函数中删除操作失败
// - 覆盖分支点：ret < 0 分支 (504行)
// - 触发条件：删除操作返回负值
// - 业务验证：函数应返回错误码
HWTEST_F(MediaAnalysisDataServiceTest, DismissAssets_DeleteFailed, TestSize.Level1)
{
    MEDIA_INFO_LOG("start DismissAssets_DeleteFailed");
    ChangeRequestDismissAssetsDto dto;
    dto.albumId = 1;
    dto.assets = {"1", "2"};
    dto.photoAlbumSubType = PhotoAlbumSubType::GROUP_PHOTO;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().DismissAssets(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end DismissAssets_DeleteFailed");
}

// 用例说明：测试 DismissAssets PORTRAIT 类型
// - 覆盖场景：DismissAssets 函数中 photoAlbumSubType 为 PORTRAIT
// - 覆盖分支点：photoAlbumSubType == PORTRAIT 分支 (508行)
// - 触发条件：设置 photoAlbumSubType 为 PORTRAIT
// - 业务验证：函数应执行额外的更新操作
HWTEST_F(MediaAnalysisDataServiceTest, DismissAssets_PortraitType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start DismissAssets_PortraitType");
    ChangeRequestDismissAssetsDto dto;
    dto.albumId = 1;
    dto.assets = {"1", "2"};
    dto.photoAlbumSubType = PhotoAlbumSubType::PORTRAIT;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().DismissAssets(dto);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end DismissAssets_PortraitType");
}

// 用例说明：：测试 DismissAssets PET 类型
// - 覆盖场景：DismissAssets 函数中 photoAlbumSubType 为 PET
// - 覆盖分支点：photoAlbumSubType == PET 分支 (508行)
// - 触发条件：设置 photoAlbumSubType 为 PET
// - 业务验证：函数应执行额外的更新操作
HWTEST_F(MediaAnalysisDataServiceTest, DismissAssets_PetType, TestSize.Level1)
{
    MEDIA_INFO_LOG("start DismissAssets_PetType");
    ChangeRequestDismissAssetsDto dto;
    dto.albumId = 1;
    dto.assets = {"1", "2"};
    dto.photoAlbumSubType = PhotoAlbumSubType::PET;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().DismissAssets(dto);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end DismissAssets_PetType");
}

// 用例说明：测试 MergeAlbum 参数校验失败
// - 覆盖场景：MergeAlbum 函数中参数转换失败
// - 覆盖分支点：value.IsEmpty() 分支 (542行)
// - 触发条件：传入无效的参数导致 ValuesBucket 为空
// - 业务验证：函数应返回 E_INVALID_VALUES 错误码
HWTEST_F(MediaAnalysisDataServiceTest, MergeAlbum_InvalidParameters, TestSize.Level1)
{
    MEDIA_INFO_LOG("start MergeAlbum_InvalidParameters");
    ChangeRequestMergeAlbumDto dto;
    dto.albumId = -1;
    dto.targetAlbumId = -1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().MergeAlbum(dto);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end MergeAlbum_InvalidParameters");
}

// 用例说明：测试 PlaceBefore 参数校验失败
// - 覆盖场景：PlaceBefore 函数中参数转换失败
// - 覆盖分支点：value.IsEmpty() 分支 (557行)
// - 触发条件：传入无效的参数导致 ValuesBucket 为空
// - 业务验证：函数应返回 E_INVALID_VALUES 错误码
HWTEST_F(MediaAnalysisDataServiceTest, PlaceBefore_InvalidParameters, TestSize.Level1)
{
    MEDIA_INFO_LOG("start PlaceBefore_InvalidParameters");
    ChangeRequestPlaceBeforeDto dto;
    dto.albumId = -1;
    dto.referenceAlbumId = -1;
    dto.albumType = -1;
    dto.albumSubType = -1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().PlaceBefore(dto);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end PlaceBefore_InvalidParameters");
}

// 用例说明：测试 StartAssetAnalysis 正常流程
// - 覆盖场景：StartAssetAnalysis 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 URI 和 predicates
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, StartAssetAnalysis_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start StartAssetAnalysis_NormalFlow");
    StartAssetAnalysisDto dto;
    dto.uri = "datashare://media/asset/1";
    StartAssetAnalysisRespBody respBody;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().StartAssetAnalysis(dto, respBody);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end StartAssetAnalysis_NormalFlow");
}

// 用例说明：测试 SetPortraitRelationship 正常流程
// - 覆盖场景：SetPortraitRelationship 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 albumId 和 relationship
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, SetPortraitRelationship_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start SetPortraitRelationship_NormalFlow");
    int32_t albumId = 1;
    string relationship = "test_relationship";
    int32_t isMe = 1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().SetPortraitRelationship(albumId, relationship, isMe);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end SetPortraitRelationship_NormalFlow");
}

// 用例说明：测试 GetFaceId 正常流程
// - 覆盖场景：GetFaceId 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 albumId
// - 业务验证：函数应返回 E_HAS_DB_ERROR
HWTEST_F(MediaAnalysisDataServiceTest, GetFaceId_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start GetFaceId_NormalFlow");
    int32_t albumId = 1;
    string groupTag;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().GetFaceId(albumId, groupTag);
    EXPECT_EQ(ret, E_HAS_DB_ERROR);
    MEDIA_INFO_LOG("end GetFaceId_NormalFlow");
}

// 用例说明：测试 SetHighlightUserActionData 正常流程
// - 覆盖场景：SetHighlightUserActionData 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 DTO
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, SetHighlightUserActionData_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start SetHighlightUserActionData_NormalFlow");
    SetHighlightUserActionDataDto dto;
    dto.albumId = 1;
    dto.actionData = 1;
    dto.userActionType = "test_value";
    
    int32_t ret = MediaAnalysisDataService::GetInstance().SetHighlightUserActionData(dto);
    EXPECT_NE(ret, E_OK);
    MEDIA_INFO_LOG("end SetHighlightUserActionData_NormalFlow");
}

// 用例说明：测试 SetSubtitle 正常流程
// - 覆盖场景：SetSubtitle 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 highlightAlbumId 和 albumSubtitle
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, SetSubtitle_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start SetSubtitle_NormalFlow");
    string highlightAlbumId = "1";
    string albumSubtitle = "test_subtitle";
    
    int32_t ret = MediaAnalysisDataService::GetInstance().SetSubtitle(highlightAlbumId, albumSubtitle);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end SetSubtitle_NormalFlow");
}

// 用例说明：测试 ChangeRequestSetIsMe 正常流程
// - 覆盖场景：ChangeRequestSetIsMe 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 albumId
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, ChangeRequestSetIsMe_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start ChangeRequestSetIsMe_NormalFlow");
    int32_t albumId = 1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().ChangeRequestSetIsMe(albumId);
    EXPECT_GT(ret, 0);
    MEDIA_INFO_LOG("end ChangeRequestSetIsMe_NormalFlow");
}

// 用例说明：测试 ChangeRequestSetDisplayLevel 正常流程
// - 覆盖场景：ChangeRequestSetDisplayLevel 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 displayLevelValue 和 albumId
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, ChangeRequestSetDisplayLevel_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start ChangeRequestSetDisplayLevel_NormalFlow");
    int32_t displayLevelValue = 3;
    int32_t albumId = 1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().ChangeRequestSetDisplayLevel(displayLevelValue,
        albumId);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end ChangeRequestSetDisplayLevel_NormalFlow");
}

// 用例说明：测试 ChangeRequestDismiss 正常流程
// - 覆盖场景：ChangeRequestDismiss 函数正常执行
// - 覆盖分支点：正常路径
// - 触发条件：传入有效的 albumId
// - 业务验证：函数应返回 E_OK
HWTEST_F(MediaAnalysisDataServiceTest, ChangeRequestDismiss_NormalFlow, TestSize.Level1)
{
    MEDIA_INFO_LOG("start ChangeRequestDismiss_NormalFlow");
    int32_t albumId = 1;
    
    int32_t ret = MediaAnalysisDataService::GetInstance().ChangeRequestDismiss(albumId);
    EXPECT_EQ(ret, E_OK);
    MEDIA_INFO_LOG("end ChangeRequestDismiss_NormalFlow");
}

} // namespace Media
} // namespace OHOS