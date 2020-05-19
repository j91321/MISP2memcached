def filter(event)
    ids = event.get("[enrich][tmp]").split(',')
    ids.each do |item|
        key_value = item.split("#")
        if !event.get('[misp][event_id]')
            event.set('[misp][event_id]', [key_value[0]])
            event.set('[misp][type]', [key_value[1]])
        else
            event.set('[misp][event_id]', event.get('[misp][event_id]') + [key_value[0]])
            event.set('[misp][type]', event.get('[misp][type]') + [key_value[1]])
        end
    end
	return [event]
end