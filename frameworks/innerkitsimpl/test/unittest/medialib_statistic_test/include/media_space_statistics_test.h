/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef MEDIA_SPACE_STATISTICS_TEST_H
#define MEDIA_SPACE_STATISTICS_TEST_H

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <sys/sendfile.h>
#include <sys/timeb.h>
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "media_data_ability_const.h"
#include "media_log.h"
#include "media_volume.h"
#include "media_library_manager.h"
#include "system_ability_definition.h"
#include "datashare_helper.h"

namespace OHOS {
    namespace Media {
        class MediaSpaceStatisticsTest : public testing::Test {
        public:
            static void SetUpTestCase(void);
            static void TearDownTestCase(void);
            void SetUp();
            void TearDown();
        };

    } // namespace Media
} // namespace OHOS
#endif // MEDIA_SPACE_STATISTICS_TEST_H
