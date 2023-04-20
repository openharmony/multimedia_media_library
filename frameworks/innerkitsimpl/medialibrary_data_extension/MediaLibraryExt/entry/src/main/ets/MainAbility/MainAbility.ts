import Ability from '@ohos.app.ability.UIAbility';

export default class MainAbility extends Ability {
  onCreate(want, launchParam): void {
    console.log('[Demo] MainAbility onCreate');
    globalThis.abilityWant = want;
  }

  onDestroy(): void {
    console.log('[Demo] MainAbility onDestroy');
  }

  onWindowStageCreate(windowStage): void {
    // Main window is created, set main page for this ability
    console.log('[Demo] MainAbility onWindowStageCreate');
    windowStage.setUIContent(this.context, 'pages/index', null);
  }

  onWindowStageDestroy(): void {
    // Main window is destroyed, release UI related resources
    console.log('[Demo] MainAbility onWindowStageDestroy');
  }

  onForeground(): void {
    // Ability has brought to foreground
    console.log('[Demo] MainAbility onForeground');
  }

  onBackground(): void {
    // Ability has back to background
    console.log('[Demo] MainAbility onBackground');
  }
};
