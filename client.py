from aiohttp import ClientSession
import asyncio
from settings import URL_USER, URL_ADV


async def main():
    async with ClientSession() as session:
#        response = await session.post(url=f'{URL_USER}/',
#                                      json={'name': 'name_1',
#                                            'password': '1234567890'})
#        response = await session.get(url=f'{URL_USER}/1')
#        response = await session.get(url=f'{URL_USER}/')
#        response = await session.delete(url=f'{URL_USER}/1')
#        response = await session.patch(url=f'{URL_USER}/1',
#                                       json={'name': 'name_1',
#                                             'password': '0987654321'})
#        response = await session.get(url=f'{URL_ADV}/')
#        response = await session.get(url=f'{URL_ADV}/1')
#        response = await session.post(url=f'{URL_ADV}/',
#                                      headers={'Authorization': '1234567890'},
#                                      json={'header': 'header_1',
#                                            'owner_id': 1,
#                                            'description': 'description_1'})
#        response = await session.patch(url=f'{URL_ADV}/1',
#                                       headers={'Id': '1',
#                                                'Authorization': '1234567890'},
#                                       json={'header': 'header_2',
#                                             'description': 'description_2'})
#        response = await session.delete(url=f'{URL_ADV}/1',
#                                        headers={'Id': '1',
#                                                 'Authorization': '1234567890'})
        print(f'{response.status=}')
        print(await response.text())

asyncio.run(main())
