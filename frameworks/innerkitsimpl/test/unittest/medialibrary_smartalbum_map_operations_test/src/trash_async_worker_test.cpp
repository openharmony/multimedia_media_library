/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "medialibrary_smartalbum_map_operations_test.h"
#include "medialibrary_unistore_manager.h"
#include "ability_context_impl.h"
#define private public
#include "trash_async_worker.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS {
namespace Media {
HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, TrashAsyncWorker_GetInstance_test_001, TestSize.Level0)
{
    shared_ptr<TrashAsyncTaskWorker> asyncWorker = TrashAsyncTaskWorker::GetInstance();
    EXPECT_EQ((asyncWorker != nullptr), true);

    shared_ptr<TrashAsyncTaskWorker> asyncWorker1 = TrashAsyncTaskWorker::GetInstance();
    EXPECT_EQ((asyncWorker1 != nullptr), true);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, TrashAsyncWorker_TrashAsyncTaskWorker_test_001, TestSize.Level0)
{
    TrashAsyncTaskWorker *asyncWorker = new TrashAsyncTaskWorker();
    EXPECT_EQ((asyncWorker->asyncWorkerInstance_ != nullptr), true);
    asyncWorker->Init();
    EXPECT_EQ((asyncWorker->asyncWorkerInstance_ != nullptr), true);
    asyncWorker->Interrupt();
    EXPECT_EQ((asyncWorker->asyncWorkerInstance_ != nullptr), true);
    asyncWorker->StartWorker();
    EXPECT_EQ((asyncWorker->asyncWorkerInstance_ != nullptr), true);
}

HWTEST_F(MediaLibrarySmartalbumMapOperationsTest, TrashAsyncWorker_TrashAsyncTaskWorker_test_002, TestSize.Level0)
{
    TrashAsyncTaskWorker *asyncWorker1 = new TrashAsyncTaskWorker();
    EXPECT_EQ((asyncWorker1->asyncWorkerInstance_ != nullptr), true);
    asyncWorker1->Init();
    EXPECT_EQ((asyncWorker1->asyncWorkerInstance_ != nullptr), true);
    asyncWorker1->Interrupt();
    EXPECT_EQ((asyncWorker1->asyncWorkerInstance_ != nullptr), true);
    asyncWorker1->StartWorker();
    EXPECT_EQ((asyncWorker1->asyncWorkerInstance_ != nullptr), true);
}
}
}
