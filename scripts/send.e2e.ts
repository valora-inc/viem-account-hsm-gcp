import * as $ from 'shelljs'

it('sends successfully', () => {
  const result = $.exec('yarn ts-node ./scripts/send.ts')
  expect(result.code).toBe(0)
})
