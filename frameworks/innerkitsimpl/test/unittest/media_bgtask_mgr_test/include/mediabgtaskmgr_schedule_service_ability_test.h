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

#ifndef MEDIABGTASKMGR_SCHEDULE_SERVICE_ABILITY_H
#define MEDIABGTASKMGR_SCHEDULE_SERVICE_ABILITY_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#define private public
#define protected public
#include "media_bgtask_schedule_service_ability.h"
#include "media_bgtask_schedule_service.h"
#undef protected
#undef private

namespace OHOS {
namespace MediaBgtaskSchedule {
static const int32_t E_OK = 0;

class MediaBgtaskMgrScheduleServiceAbilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class MediaBgtaskScheduleServiceAbilityMock : public MediaBgtaskScheduleServiceAbility {
public:
    int32_t systemAbilityIdTmp;

    MediaBgtaskScheduleServiceAbilityMock(const int32_t systemAbilityId, bool runOnCreate)
        : MediaBgtaskScheduleServiceAbility(systemAbilityId, runOnCreate)
    {
        systemAbilityIdTmp = systemAbilityId;
    }
    ~MediaBgtaskScheduleServiceAbilityMock() {}

    bool Publish(sptr<IRemoteObject> systemAbility)
    {
        return systemAbilityIdTmp != E_OK;
    }
};
} // namespace MediaBgtaskSchedule
} // namespace OHOS

#endif // MEDIABGTASKMGR_SCHEDULE_SERVICE_ABILITY_H
