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
#include "medialibrary_cover_position_parser_test.h"

#define private public
#include "cover_position_parser.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {

void MediaLibraryCoverPositionParserTest::SetUpTestCase(void) {}

void MediaLibraryCoverPositionParserTest::TearDownTestCase(void) {}

// SetUp:Execute before each test case
void MediaLibraryCoverPositionParserTest::SetUp() {}

void MediaLibraryCoverPositionParserTest::TearDown(void) {}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : AddTask
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add task success
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_AddTask_test_001, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->processing_ = true;
    bool ret = instance->AddTask("/test", "file://media");
    EXPECT_EQ(ret, true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : AddTask
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add task fail
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_AddTask_test_002, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->processing_ = true;
    bool ret = false;
    for (int i = 0; i < 101; i++) {
        ret = instance->AddTask("/test" + to_string(i), "file://media/" + to_string(i));
    }
    EXPECT_EQ(ret, false);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : AddTask
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_AddTask_test_003, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    string path = "/storage/cloud/files/Photo/1/IMG_000000000_000.jpg";
    string fileUri = "file://media/Photo/38/IMG_000000000_000/111.jpg";
    bool ret = instance->AddTask(path, fileUri);
    EXPECT_EQ(ret, true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : AddTask
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_AddTask_test_004, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    string path = "/storage/cloud/files/Photo/1/IMG_000000000_000.jpg";
    string fileUri = "file://media/Photo/38/IMG_000000000_000/111.jpg";
    instance->tasks_.push(make_pair(path, fileUri));
    bool ret = instance->AddTask(path, fileUri);
    EXPECT_EQ(ret, true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : StartTask
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_StartTask_test_001, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->StartTask();
    EXPECT_TRUE(true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : ProcessCoverPosition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_ProcessCoverPosition_test_001, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->ProcessCoverPosition();
    EXPECT_TRUE(true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : ProcessCoverPosition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_ProcessCoverPosition_test_002, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->processing_ = true;
    string path = "/storage/cloud/files/Photo/1/IMG_000000000_000.jpg";
    string fileUri = "file://media/Photo/38/IMG_000000000_000/111.jpg";
    instance->tasks_.push(make_pair(path, fileUri));
    instance->ProcessCoverPosition();
    EXPECT_EQ(instance->tasks_.size(), 0);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : ProcessCoverPosition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_ProcessCoverPosition_test_003, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    instance->processing_ = true;
    string path = "/storage/cloud/files/Photo/1/IMG_000000000_000.jpg";
    string fileUri = "file://media/Photo/38/IMG_000000000_000/111.jpg";
    bool ret = instance->AddTask(path, fileUri);
    instance->ProcessCoverPosition();
    EXPECT_EQ(ret, true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : UpdateCoverPosition
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_UpdateCoverPosition_test_001, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    string path = "/storage/cloud/files/Photo/1/IMG_000000000_000.jpg";
    instance->UpdateCoverPosition(path);
    EXPECT_TRUE(true);
}

/*
 * Feature : MediaLibraryCoverPositionParserTest
 * Function : SendUpdateNotify
 * SubFunction : NA
 * FunctionPoints : NA
 * EnvContions : NA
 * CaseDescription : add and start task
 */
HWTEST_F(MediaLibraryCoverPositionParserTest, medialib_SendUpdateNotify_test_001, TestSize.Level1)
{
    shared_ptr<CoverPositionParser> instance = make_shared<CoverPositionParser>();
    string fileUri = "file://media/Photo/38/IMG_000000000_000/111.jpg";
    instance->SendUpdateNotify(fileUri);
    EXPECT_TRUE(true);
}
} // namespace Media
} // namespace OHOS