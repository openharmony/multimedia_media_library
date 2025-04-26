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
#include "medialibrary_rdb_test.h"
#include "medialibrary_errno.h"
#include "runtime.h"
#include "uri.h"
#define private public
#include "media_datashare_stub_impl.h"
#undef private

using namespace std;
using namespace OHOS;
using namespace testing::ext;

namespace OHOS::Media {
HWTEST_F(MediaLibraryRdbTest, medialibrary_GetOwner_test_001, TestSize.Level1)
{
    napi_env env = nullptr;
    shared_ptr<DataShare::MediaDataShareExtAbility> extension;
    DataShare::MediaDataShareStubImpl mediaDataShareStubImpl(extension, env);
    extension = mediaDataShareStubImpl.GetOwner();
    EXPECT_EQ(extension, nullptr);
}

HWTEST_F(MediaLibraryRdbTest, medialibrary_GetOwner_test_002, TestSize.Level1)
{
    const std::unique_ptr<AbilityRuntime::Runtime> runtime;
    AbilityRuntime::MediaDataShareExtAbility* mediaDataShare;
    mediaDataShare = AbilityRuntime::MediaDataShareExtAbility::Create(runtime);
    EXPECT_EQ(mediaDataShare != nullptr, true);

    napi_env env = nullptr;
    shared_ptr<DataShare::MediaDataShareExtAbility> extension(mediaDataShare);
    DataShare::MediaDataShareStubImpl mediaDataShareStubImpl(extension, env);
    extension = mediaDataShareStubImpl.GetOwner();
    EXPECT_EQ((extension != nullptr), true);
}
} // namespace OHOS::Media