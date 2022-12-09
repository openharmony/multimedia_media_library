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
#ifndef CREATE_DELETE_DIRECTORY_H
#define CREATE_DELETE_DIRECTORY_H

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include "system_ability_definition.h"
#include "userfile_manager_types.h"
#include "gtest/gtest.h"
#include "iservice_registry.h"
#include "media_log.h"
#include "media_volume.h"
#include "medialibrary_db_const.h"
#include "medialibrary_errno.h"
#include "media_library_manager.h"
#include "datashare_helper.h"

namespace OHOS {
namespace Media {
class CreateDeleteDirectory : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

} // namespace Media
} // namespace OHOS
#endif // CREATE_DELETE_DIRECTORY_H
