import Ability from '@ohos.app.ability.UIAbility';
import AbilityDelegatorRegistry from '@ohos.application.abilityDelegatorRegistry';
import { Hypium } from 'hypium/index';
import testsuite from '../test/List.test';

export default class TestAbility extends Ability {
  onCreate(want, launchParam): void {
    console.log('TestAbility onCreate');
    let abilityDelegator;
    abilityDelegator = AbilityDelegatorRegistry.getAbilityDelegator();
    let abilityDelegatorArguments;
    abilityDelegatorArguments = AbilityDelegatorRegistry.getArguments();
    console.info('start run testcase!!!');
    Hypium.hypiumTest(abilityDelegator, abilityDelegatorArguments, testsuite);
  }

  onDestroy(): void {
    console.log('TestAbility onDestroy');
  }

  onWindowStageCreate(windowStage): void {
    console.log('TestAbility onWindowStageCreate');
    windowStage.setUIContent(this.context, 'TestAbility/pages/index', null);

    globalThis.abilityContext = this.context;
  }

  onWindowStageDestroy(): void {
    console.log('TestAbility onWindowStageDestroy');
  }

  onForeground(): void {
    console.log('TestAbility onForeground');
  }

  onBackground(): void {
    console.log('TestAbility onBackground');
  }
};