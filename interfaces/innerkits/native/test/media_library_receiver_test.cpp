/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include <cstdio>
#include <unistd.h>
#include "media_event_receiver.h"
using namespace OHOS::Media;
int main(int argc, char *argv[])
{
    for (int i = 0; i < 100000; i++) {
        std::string testEvent;

        MediaEventReceiver mer;
        mer.Init();

        printf("=================DistributedDevicesBatchRecycle==================\n");
        testEvent = "DistributedDevicesBatchRecyclePolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================DistributedDevicesBatchRecycle==================\n");
        testEvent = "DistributedDevicesBatchRecyclePolicy02";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================EmptyFolderBatchRecycle=====================\n");
        testEvent = "EmptyFolderBatchRecyclePolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================EmptyFolderBatchRecycle=====================\n");
        testEvent = "EmptyFolderBatchRecyclePolicy02";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================LCDBatchRecycle=====================\n");
        testEvent = "LCDBatchRecyclePolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================LCDBatchRecycle=====================\n");
        testEvent = "LCDBatchRecyclePolicy02";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================ThumbnailBatchGen=====================\n");
        testEvent = "ThumbnailBatchGenPolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================ThumbnailBatchGen=====================\n");
        testEvent = "ThumbnailBatchGenPolicy02";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================ThumbnailBatchRecycle=====================\n");
        testEvent = "ThumbnailBatchRecyclePolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================ThumbnailBatchRecycle=====================\n");
        testEvent = "ThumbnailBatchRecyclePolicy02";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================TrashFileBatchRecycle=====================\n");
        testEvent = "TrashFileBatchRecyclePolicy01";
        mer.OnEvent(testEvent);
        sleep(1);

        printf("=================TrashFileBatchRecycle=====================\n");
        testEvent = "TrashFileBatchRecyclePolicy02";
        mer.OnEvent(testEvent);
        sleep(1);
    }

    return 0;
}
